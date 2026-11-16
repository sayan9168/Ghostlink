//! # `ghostlink_core::crypto` — Module 1A
//!
//! Zero-knowledge cryptographic identity, blind `SPAKE2` rendezvous, `ChaCha20-Poly1305`
//! signaling envelopes, `Noise_XXpsk2` E2EE session negotiation, human-verifiable `SAS`
//! derivation, Mandatory Host Consent gating, and dual-domain stateless AEAD transport.

pub mod error;
pub mod identity;
pub mod noise;
pub mod rendezvous;
pub mod replay;

pub use error::CryptoError;
pub use identity::{
    BlindRoomId, OneTimePin, PairingQrPayload, SecretBytes32, SessionId, DEFAULT_QR_TTL_SECS,
    MAX_QR_TTL_SECS, SESSION_ID_CHARS, SESSION_ID_LEN,
};
pub use noise::{
    ChannelDomain, EphemeralNoiseKeypair, NoiseHandshake, NoiseTransport, SasCode,
    MAX_HANDSHAKE_PAYLOAD_BYTES, MAX_TRANSPORT_PAYLOAD_BYTES, NOISE_PATTERN, TRANSPORT_HEADER_LEN,
};
pub use rendezvous::{
    BlindSignalingChannel, DerivedPairingKeys, PeerRole, Spake2Handshake, AEAD_TAG_LEN,
    MAX_SIGNALING_PLAINTEXT_BYTES, SIGNALING_ENVELOPE_VERSION, SIGNALING_HEADER_LEN,
};
pub use replay::{SlidingReplayWindow, REPLAY_WINDOW_SIZE};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn session_id_crockford_roundtrip_and_lookalike_normalization() {
        let sid = SessionId::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xFF]);
        let formatted = sid.to_display_code();
        assert_eq!(formatted.len(), 19);

        // Simulate human transcription with lowercase, spaces, O->0, I/l->1
        let noisy_human_input = formatted
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "O")
            .replace('1', "l");

        let parsed = SessionId::parse(&noisy_human_input).expect("should normalize Crockford aliases");
        assert_eq!(parsed, sid);

        // 'U' is excluded from Crockford alphabet
        assert_eq!(
            SessionId::parse("UUUU-UUUU-UUUU-UUUU"),
            Err(CryptoError::InvalidSessionId)
        );
        // Truncated input rejected
        assert_eq!(
            SessionId::parse("ABCD-EFGH"),
            Err(CryptoError::InvalidSessionId)
        );
    }

    #[test]
    fn one_time_pin_validation_and_debug_redaction() {
        let pin = OneTimePin::generate();
        assert_eq!(pin.as_bytes().len(), 6);
        assert!(pin.as_bytes().iter().all(u8::is_ascii_digit));

        let parsed = OneTimePin::parse(" 849-201 ").expect("valid grouped PIN");
        assert_eq!(parsed.as_bytes(), b"849201");
        assert_eq!(parsed.to_grouped_display().as_str(), "849-201");

        // Debug output must never leak PIN digits
        let debug_repr = format!("{parsed:?}");
        assert!(!debug_repr.contains("849"));
        assert!(debug_repr.contains("REDACTED"));

        assert_eq!(OneTimePin::parse("12345"), Err(CryptoError::InvalidPin));
        assert_eq!(OneTimePin::parse("12345a"), Err(CryptoError::InvalidPin));
    }

    #[test]
    fn qr_payload_uri_roundtrip_ttl_and_pollution_guards() {
        let sid = SessionId::generate();
        let host_kp = EphemeralNoiseKeypair::generate().expect("keygen");
        let now = 1_794_800_000_u64;

        let qr = PairingQrPayload::generate(sid, *host_kp.public_key(), now, DEFAULT_QR_TTL_SECS)
            .expect("valid TTL");
        let uri = qr.to_uri();

        let decoded = PairingQrPayload::from_uri(&uri, now + 30).expect("within TTL");
        assert_eq!(decoded, qr);

        // Expired QR rejected
        assert_eq!(
            PairingQrPayload::from_uri(&uri, now + DEFAULT_QR_TTL_SECS + 1),
            Err(CryptoError::QrPayloadExpired)
        );

        // Parameter pollution rejected
        let polluted = format!("{}&extra=evil", uri.as_str());
        assert!(matches!(
            PairingQrPayload::from_uri(&polluted, now),
            Err(CryptoError::InvalidQrUri { .. })
        ));
    }

    #[test]
    fn spake2_blind_signaling_and_wrong_pin_rejection() {
        let sid = SessionId::generate();
        let correct_pin = OneTimePin::parse("482-910").expect("pin");
        let wrong_pin = OneTimePin::parse("482-911").expect("pin");

        // Honest pairing
        let (client_spake, client_msg) = Spake2Handshake::start(PeerRole::Client, sid, &correct_pin);
        let (host_spake, host_msg) = Spake2Handshake::start(PeerRole::Host, sid, &correct_pin);

        let client_keys = client_spake.finish(&host_msg).expect("spake2 finish");
        let host_keys = host_spake.finish(&client_msg).expect("spake2 finish");

        let mut client_sig = BlindSignalingChannel::new(PeerRole::Client, &client_keys);
        let mut host_sig = BlindSignalingChannel::new(PeerRole::Host, &host_keys);

        // Mutual key confirmation succeeds
        host_sig
            .verify_peer_confirmation_tag(client_sig.local_confirmation_tag())
            .expect("client tag valid");
        client_sig
            .verify_peer_confirmation_tag(host_sig.local_confirmation_tag())
            .expect("host tag valid");

        // Blind SDP Offer / Answer exchange
        let sdp_offer = br#"{"type":"offer","sdp":"v=0\r\nc=IN IP4 192.168.1.44\r\n"}"#;
        let sealed_offer = client_sig.seal_frame(sdp_offer).expect("seal offer");

        // Reflection attack (server echoes frame back to sender) must fail
        assert!(matches!(
            client_sig.open_frame(&sealed_offer),
            Err(CryptoError::MalformedFrame { .. })
        ));

        let opened_offer = host_sig.open_frame(&sealed_offer).expect("open offer");
        assert_eq!(opened_offer, sdp_offer);

        // Replay of the exact same signaling envelope must fail
        assert_eq!(
            host_sig.open_frame(&sealed_offer),
            Err(CryptoError::ReplayDetected)
        );

        // Mistyped PIN must fail confirmation & AEAD decryption without leaking SDP
        let (bad_client_spake, bad_client_msg) =
            Spake2Handshake::start(PeerRole::Client, sid, &wrong_pin);
        let (host_spake2, host_msg2) = Spake2Handshake::start(PeerRole::Host, sid, &correct_pin);
        let bad_client_keys = bad_client_spake.finish(&host_msg2).expect("spake2 finish");
        let host_keys2 = host_spake2.finish(&bad_client_msg).expect("spake2 finish");

        let mut bad_client_sig = BlindSignalingChannel::new(PeerRole::Client, &bad_client_keys);
        let mut host_sig2 = BlindSignalingChannel::new(PeerRole::Host, &host_keys2);

        assert_eq!(
            host_sig2.verify_peer_confirmation_tag(bad_client_sig.local_confirmation_tag()),
            Err(CryptoError::AuthenticationFailed)
        );
        let bad_env = bad_client_sig.seal_frame(sdp_offer).expect("seal");
        assert_eq!(
            host_sig2.open_frame(&bad_env),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn qr_noise_xxpsk2_sas_match_and_rogue_host_key_detection() {
        let sid = SessionId::generate();
        let host_kp = EphemeralNoiseKeypair::generate().expect("host kp");
        let client_kp = EphemeralNoiseKeypair::generate().expect("client kp");
        let now = 1_794_800_000_u64;

        let qr_host = PairingQrPayload::generate(sid, *host_kp.public_key(), now, 120).expect("qr");
        let qr_client = PairingQrPayload::from_uri(&qr_host.to_uri(), now + 5).expect("parse qr");

        let host_keys = DerivedPairingKeys::from_qr_payload(&qr_host);
        let client_keys = DerivedPairingKeys::from_qr_payload(&qr_client);

        let mut client_hs =
            NoiseHandshake::new(PeerRole::Client, &client_kp, &client_keys).expect("client hs");
        let mut host_hs =
            NoiseHandshake::new(PeerRole::Host, &host_kp, &host_keys).expect("host hs");

        // 3-way XXpsk2 handshake
        let m1 = client_hs.write_message(b"").expect("-> e");
        assert!(host_hs.read_message(&m1).expect("read m1").is_empty());

        let m2 = host_hs.write_message(b"host-caps-v1").expect("<- e, ee, s, es, psk");
        assert_eq!(client_hs.read_message(&m2).expect("read m2"), b"host-caps-v1");

        let m3 = client_hs.write_message(b"client-caps-v1").expect("-> s, se");
        assert_eq!(host_hs.read_message(&m3).expect("read m3"), b"client-caps-v1");

        let (_client_tp, client_sas) = client_hs.into_transport().expect("client transport");
        let (_host_tp, host_sas) = host_hs.into_transport().expect("host transport");

        assert_eq!(client_sas, host_sas);
        assert_eq!(client_sas.numeric().len(), 7);
        assert_eq!(client_sas.words().len(), 4);

        // Rogue Responder using a different static keypair (even if QR secret leaked) is caught!
        let rogue_kp = EphemeralNoiseKeypair::generate().expect("rogue kp");
        let mut client_hs2 =
            NoiseHandshake::new(PeerRole::Client, &client_kp, &client_keys).expect("client hs2");
        let mut rogue_hs =
            NoiseHandshake::new(PeerRole::Host, &rogue_kp, &host_keys).expect("rogue hs");

        let r1 = client_hs2.write_message(b"").expect("m1");
        rogue_hs.read_message(&r1).expect("r1");
        let r2 = rogue_hs.write_message(b"").expect("m2");
        client_hs2.read_message(&r2).expect("r2");
        let r3 = client_hs2.write_message(b"").expect("m3");
        rogue_hs.read_message(&r3).expect("r3");

        assert!(matches!(
            client_hs2.into_transport(),
            Err(CryptoError::RemoteKeyMismatch)
        ));
    }

    #[test]
    fn mandatory_consent_gate_lossy_udp_reordering_and_dos_resistance() {
        let sid = SessionId::generate();
        let pin = OneTimePin::parse("901-774").expect("pin");
        let (c_spake, c_pub) = Spake2Handshake::start(PeerRole::Client, sid, &pin);
        let (h_spake, h_pub) = Spake2Handshake::start(PeerRole::Host, sid, &pin);
        let c_keys = c_spake.finish(&h_pub).expect("c finish");
        let h_keys = h_spake.finish(&c_pub).expect("h finish");

        let c_kp = EphemeralNoiseKeypair::generate().expect("c kp");
        let h_kp = EphemeralNoiseKeypair::generate().expect("h kp");

        let mut c_hs = NoiseHandshake::new(PeerRole::Client, &c_kp, &c_keys).expect("c hs");
        let mut h_hs = NoiseHandshake::new(PeerRole::Host, &h_kp, &h_keys).expect("h hs");

        let m1 = c_hs.write_message(b"").expect("m1");
        h_hs.read_message(&m1).expect("m1");
        let m2 = h_hs.write_message(b"").expect("m2");
        c_hs.read_message(&m2).expect("m2");
        let m3 = c_hs.write_message(b"").expect("m3");
        h_hs.read_message(&m3).expect("m3");

        let (client_tp, _) = c_hs.into_transport().expect("c tp");
        let (host_tp, _) = h_hs.into_transport().expect("h tp");
        let client_tp = Arc::new(client_tp);
        let host_tp = Arc::new(host_tp);

        // 1. Host media gate MUST start locked until human consent is granted
        assert!(!host_tp.is_consent_granted());
        assert_eq!(
            host_tp.seal(ChannelDomain::Media, b"h264-idr-slice"),
            Err(CryptoError::ConsentRequired)
        );

        // Control plane works to communicate consent approval
        let approval_pkt = host_tp
            .seal(ChannelDomain::Control, b"CONSENT_APPROVED")
            .expect("ctrl seal");
        assert_eq!(
            client_tp
                .open(ChannelDomain::Control, &approval_pkt)
                .expect("ctrl open"),
            b"CONSENT_APPROVED"
        );

        // 2. Grant consent -> unlock media streaming
        host_tp.grant_user_consent();
        assert!(host_tp.is_consent_granted());

        // 3. Simulate heavy 4G/5G packet loss + out-of-order UDP delivery across 1,200 NALUs
        let mut media_frames = Vec::with_capacity(1200);
        for i in 0..1200_u32 {
            let pkt = host_tp
                .seal(ChannelDomain::Media, &i.to_be_bytes())
                .expect("media seal");
            media_frames.push(pkt);
        }

        // Cross-channel injection (feeding Media packet into Control channel) MUST fail
        assert!(matches!(
            client_tp.open(ChannelDomain::Control, &media_frames[0]),
            Err(CryptoError::MalformedFrame { .. })
        ));

        // Drop packets 0..15 completely; deliver [25, 20, 24, 21] out of order
        for &idx in &[25_usize, 20, 24, 21] {
            let plain = client_tp
                .open(ChannelDomain::Media, &media_frames[idx])
                .expect("reordered packet within 1024-window must decrypt");
            assert_eq!(plain, (idx as u32).to_be_bytes());
        }

        // Duplicate delivery of #20 rejected
        assert_eq!(
            client_tp.open(ChannelDomain::Media, &media_frames[20]),
            Err(CryptoError::ReplayDetected)
        );

        // Replay-window poisoning DoS test: attacker forges seq = 5_000_000 with bad MAC
        let mut forged = media_frames[30].clone();
        let forged_nonce: u64 = (u64::from(ChannelDomain::Media.tag_byte()) << 56) | 5_000_000;
        forged[..TRANSPORT_HEADER_LEN].copy_from_slice(&forged_nonce.to_be_bytes());
        assert_eq!(
            client_tp.open(ChannelDomain::Media, &forged),
            Err(CryptoError::AuthenticationFailed)
        );

        // Legitimate packet #30 still decrypts cleanly (window was NOT poisoned!)
        assert_eq!(
            client_tp
                .open(ChannelDomain::Media, &media_frames[30])
                .expect("legit #30"),
            30_u32.to_be_bytes()
        );

        // Jump to packet #1150 -> scrolls window past packet #22 -> stale #22 rejected
        client_tp
            .open(ChannelDomain::Media, &media_frames[1150])
            .expect("jump to #1150");
        assert_eq!(
            client_tp.open(ChannelDomain::Media, &media_frames[22]),
            Err(CryptoError::ReplayDetected)
        );

        // Meanwhile Control channel's isolated window was unaffected by 1,150 Media packets!
        let touch_pkt = client_tp
            .seal(ChannelDomain::Control, b"TOUCH_DOWN(0.5,0.5)")
            .expect("ctrl seal");
        assert_eq!(
            host_tp
                .open(ChannelDomain::Control, &touch_pkt)
                .expect("ctrl open"),
            b"TOUCH_DOWN(0.5,0.5)"
        );

        // 4. Revoking consent immediately blocks further Host media frames
        host_tp.revoke_user_consent();
        assert_eq!(
            host_tp.seal(ChannelDomain::Media, b"post-revoke-frame"),
            Err(CryptoError::ConsentRequired)
        );
    }
}
