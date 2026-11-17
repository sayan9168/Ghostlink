//! # `ghostlink-signal` — Module 2A
//!
//! Zero-log, RAM-only blind WebSocket rendezvous signaling server and stateless
//! ephemeral `coturn` credential minter for **GhostLink**.
//!
//! ## Zero-Knowledge & Zero-Log Guarantees
//! 1. **No Logging Infrastructure**: Deliberately excludes `tracing-subscriber`, `env_logger`,
//!    access-log middlewares, and stdout IP/token printing.
//! 2. **Cryptographically Blind Routing**: Routes opaque binary frames exclusively by 256-bit
//!    `BlindRoomId` tokens (`HKDF-SHA256(SessionId)`); plaintext `Text` WebSocket frames are
//!    rejected with `1003 Unsupported Data`.
//! 3. **Blinded In-Memory Rate Limiting**: Client IPs are hashed via `HMAC-SHA256` with a
//!    15-minute rotating CSPRNG RAM key so raw client IP addresses are never stored in memory.
//! 4. **Single-Shot Rooms**: Each `BlindRoomId` permits at most one `Host` and one `Client`
//!    connection during its 60-second TTL, defeating online 6-digit PIN brute-forcing.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{
        ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, State,
    },
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use ghostlink_core::crypto::PeerRole;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub mod config;
pub mod rate_limit;
pub mod room;
pub mod turn_creds;

pub use config::{SignalConfig, SignalConfigError};
pub use rate_limit::BlindedIpRateLimiter;
pub use room::{BlindRendezvousRegistry, PeerLease, RelayError, RoomJoinError};
pub use turn_creds::{
    current_unix_secs, mint_ice_bootstrap, verify_coturn_credential, EphemeralTurnCredentials,
    IceBootstrapResponse,
};

/// Default background reaper sweep cadence (`15` seconds).
pub const DEFAULT_REAPER_INTERVAL: Duration = Duration::from_secs(15);

const WS_CLOSE_UNSUPPORTED_DATA: u16 = 1003;
const WS_CLOSE_POLICY_VIOLATION: u16 = 1008;

/// Shared, cloneable zero-log application state for the `axum` router.
#[derive(Clone)]
pub struct SignalState {
    config: Arc<SignalConfig>,
    registry: Arc<BlindRendezvousRegistry>,
    rate_limiter: Arc<BlindedIpRateLimiter>,
}

impl SignalState {
    /// Initializes a validated [`SignalState`] completely in RAM.
    pub fn new(config: SignalConfig) -> Result<Self, SignalConfigError> {
        config.validate()?;
        let registry = BlindRendezvousRegistry::new(
            config.room_ttl,
            config.max_active_rooms,
            config.max_ws_frame_bytes,
        );
        let rate_limiter =
            Arc::new(BlindedIpRateLimiter::new(config.rate_limit_burst, config.rate_limit_refill_interval));

        Ok(Self {
            config: Arc::new(config),
            registry,
            rate_limiter,
        })
    }

    /// Borrows the active [`SignalConfig`].
    #[must_use]
    pub fn config(&self) -> &SignalConfig {
        &self.config
    }

    /// Borrows the in-memory [`BlindRendezvousRegistry`].
    #[must_use]
    pub fn registry(&self) -> &Arc<BlindRendezvousRegistry> {
        &self.registry
    }

    /// Borrows the blinded token-bucket rate limiter.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<BlindedIpRateLimiter> {
        &self.rate_limiter
    }
}

/// Minimal health response omitting room counts or peer telemetry to prevent side-channel probing.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Constructs the hardened `axum` [`Router`] for GhostLink blind signaling.
pub fn build_router(state: SignalState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/v1/ice-config", post(ice_config_handler))
        .route("/v1/ws/{room_token}/{role}", get(ws_rendezvous_handler))
        .with_state(state)
}

/// Spawns the silent background reaper evicting expired rooms and idle rate-limit buckets.
#[must_use]
pub fn spawn_reaper_task(state: SignalState, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let _ = state.registry.reap_expired(now);
            state.rate_limiter.reap_idle(now);
        }
    })
}

async fn healthz_handler() -> Response {
    with_privacy_headers((StatusCode::OK, Json(HealthResponse { status: "ok" })).into_response())
}

async fn ice_config_handler(
    State(state): State<SignalState>,
    conn_info: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let client_ip = extract_ip(conn_info);
    if !state
        .rate_limiter
        .check_and_consume(client_ip, 2, Instant::now())
    {
        return with_privacy_headers(StatusCode::TOO_MANY_REQUESTS.into_response());
    }

    let payload = mint_ice_bootstrap(&state.config, current_unix_secs());
    with_privacy_headers((StatusCode::OK, Json(payload)).into_response())
}

async fn ws_rendezvous_handler(
    State(state): State<SignalState>,
    conn_info: Option<ConnectInfo<SocketAddr>>,
    Path((room_token, role_str)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    let client_ip = extract_ip(conn_info);
    if !state
        .rate_limiter
        .check_and_consume(client_ip, 1, Instant::now())
    {
        return with_privacy_headers(StatusCode::TOO_MANY_REQUESTS.into_response());
    }

    let Ok(room_key) = room::parse_blind_room_token(&room_token) else {
        return with_privacy_headers(StatusCode::BAD_REQUEST.into_response());
    };
    let Ok(peer_role) = room::parse_peer_role(&role_str) else {
        return with_privacy_headers(StatusCode::BAD_REQUEST.into_response());
    };

    let (rx, lease) = match state.registry.join_room(room_key, peer_role, Instant::now()) {
        Ok(pair) => pair,
        Err(RoomJoinError::SlotAlreadyConsumed) => {
            return with_privacy_headers(StatusCode::CONFLICT.into_response());
        }
        Err(RoomJoinError::RegistryFull) => {
            return with_privacy_headers(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
        Err(RoomJoinError::InvalidRoomToken | RoomJoinError::InvalidRole) => {
            return with_privacy_headers(StatusCode::BAD_REQUEST.into_response());
        }
    };

    let max_bytes = state.config.max_ws_frame_bytes;
    let idle_timeout = state.config.ws_idle_timeout;
    let registry = Arc::clone(&state.registry);

    let response = ws
        .max_message_size(max_bytes)
        .max_frame_size(max_bytes)
        .on_upgrade(move |socket| {
            handle_peer_socket(
                socket,
                rx,
                lease,
                registry,
                room_key,
                peer_role,
                idle_timeout,
            )
        });

    with_privacy_headers(response)
}

async fn handle_peer_socket(
    socket: WebSocket,
    mut rx: mpsc::Receiver<Bytes>,
    _lease: PeerLease,
    registry: Arc<BlindRendezvousRegistry>,
    room_key: [u8; 32],
    peer_role: PeerRole,
    idle_timeout: Duration,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    loop {
        tokio::select! {
            outbound = rx.recv() => {
                match outbound {
                    Some(binary_payload) => {
                        if ws_tx.send(Message::Binary(binary_payload)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            inbound = tokio::time::timeout(idle_timeout, ws_rx.next()) => {
                match inbound {
                    Err(_elapsed) => {
                        let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                            code: WS_CLOSE_POLICY_VIOLATION,
                            reason: Utf8Bytes::from_static("idle timeout"),
                        }))).await;
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(Err(_))) => break,
                    Ok(Some(Ok(msg))) => {
                        match msg {
                            Message::Binary(ciphertext) => {
                                if registry.relay_binary_frame(
                                    &room_key,
                                    peer_role,
                                    ciphertext,
                                    Instant::now(),
                                ).is_err() {
                                    let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                                        code: WS_CLOSE_POLICY_VIOLATION,
                                        reason: Utf8Bytes::from_static("relay policy rejected"),
                                    }))).await;
                                    break;
                                }
                            }
                            Message::Text(_) => {
                                // Enforce zero-knowledge invariant: reject plaintext frames immediately.
                                let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                                    code: WS_CLOSE_UNSUPPORTED_DATA,
                                    reason: Utf8Bytes::from_static("binary ciphertext required"),
                                }))).await;
                                break;
                            }
                            Message::Ping(_) | Message::Pong(_) => {}
                            Message::Close(_) => break,
                        }
                    }
                }
            }
        }
    }
}

fn extract_ip(conn_info: Option<ConnectInfo<SocketAddr>>) -> IpAddr {
    conn_info.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip())
}

fn with_privacy_headers(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use futures_util::{SinkExt, StreamExt};
    use ghostlink_core::crypto::{
        BlindSignalingChannel, OneTimePin, PeerRole, SessionId, Spake2Handshake,
    };
    use tokio::net::TcpListener;
    use tokio_tungstenite::{connect_async, tungstenite};

    use super::*;

    async fn spawn_test_server(config: SignalConfig) -> (SocketAddr, JoinHandle<()>) {
        let state = SignalState::new(config).expect("valid state");
        let app = build_router(state).into_make_service_with_connect_info::<SocketAddr>();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn e2e_blind_spake2_and_encrypted_sdp_rendezvous_over_ws() {
        let (addr, server_task) = spawn_test_server(SignalConfig::default()).await;

        let sid = SessionId::generate();
        let pin = OneTimePin::parse("731-904").expect("pin");
        let blind_token = sid.derive_blind_room_id().to_url_token();

        let host_url = format!("ws://{addr}/v1/ws/{blind_token}/host");
        let client_url = format!("ws://{addr}/v1/ws/{blind_token}/client");

        // 1. Android Host connects BEFORE Desktop Client and sends its SPAKE2 share immediately
        let (mut host_ws, _) = connect_async(&host_url).await.expect("host connect");
        let (host_spake, host_pub) = Spake2Handshake::start(PeerRole::Host, sid, &pin);
        host_ws
            .send(tungstenite::Message::Binary(host_pub.into()))
            .await
            .expect("host send spake2");

        // 2. Desktop Client connects later and receives the pre-join buffered Host SPAKE2 share
        let (mut client_ws, _) = connect_async(&client_url).await.expect("client connect");
        let (client_spake, client_pub) = Spake2Handshake::start(PeerRole::Client, sid, &pin);
        client_ws
            .send(tungstenite::Message::Binary(client_pub.into()))
            .await
            .expect("client send spake2");

        let rx_host_pub = client_ws
            .next()
            .await
            .expect("frame")
            .expect("ok")
            .into_data();
        let rx_client_pub = host_ws
            .next()
            .await
            .expect("frame")
            .expect("ok")
            .into_data();

        let client_keys = client_spake.finish(&rx_host_pub).expect("client spake2");
        let host_keys = host_spake.finish(&rx_client_pub).expect("host spake2");

        let mut client_sig = BlindSignalingChannel::new(PeerRole::Client, &client_keys);
        let mut host_sig = BlindSignalingChannel::new(PeerRole::Host, &host_keys);

        // 3. Exchange encrypted SDP Offer / Answer opaque to the rendezvous server
        let sdp_offer = br#"{"type":"offer","sdp":"v=0...a=ice-ufrag:secret"}"#;
        let sealed_offer = client_sig.seal_frame(sdp_offer).expect("seal");
        client_ws
            .send(tungstenite::Message::Binary(sealed_offer.into()))
            .await
            .expect("send encrypted offer");

        let relayed_offer = host_ws
            .next()
            .await
            .expect("offer")
            .expect("ok")
            .into_data();
        assert_eq!(
            host_sig.open_frame(&relayed_offer).expect("open offer"),
            sdp_offer
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn single_shot_room_blocks_second_client_pin_bruteforce() {
        let (addr, server_task) = spawn_test_server(SignalConfig::default()).await;
        let sid = SessionId::generate();
        let blind_token = sid.derive_blind_room_id().to_url_token();
        let client_url = format!("ws://{addr}/v1/ws/{blind_token}/client");

        let (mut first_client, _) = connect_async(&client_url).await.expect("first client joins");
        let _ = first_client.close(None).await;

        // Second Client join attempt on the same BlindRoomId MUST fail with HTTP 409 Conflict
        let second_attempt = connect_async(&client_url).await;
        match second_attempt {
            Err(tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), StatusCode::CONFLICT);
            }
            other => panic!("expected HTTP 409 Conflict on second Client join, got {other:?}"),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn plaintext_ws_text_frame_rejected_with_1003() {
        let (addr, server_task) = spawn_test_server(SignalConfig::default()).await;
        let sid = SessionId::generate();
        let blind_token = sid.derive_blind_room_id().to_url_token();
        let host_url = format!("ws://{addr}/v1/ws/{blind_token}/host");

        let (mut host_ws, _) = connect_async(&host_url).await.expect("connect");
        host_ws
            .send(tungstenite::Message::Text("{\"sdp\":\"leaky\"}".into()))
            .await
            .expect("send text");

        let response = host_ws.next().await.expect("close frame").expect("ok");
        match response {
            tungstenite::Message::Close(Some(cf)) => {
                assert_eq!(u16::from(cf.code), WS_CLOSE_UNSUPPORTED_DATA);
            }
            other => panic!("expected Close(1003), got {other:?}"),
        }

        server_task.abort();
    }

    #[test]
    fn coturn_hmac_minting_and_ipv6_prefix_blinded_rate_limiting() {
        let mut cfg = SignalConfig::default();
        cfg.stun_urls = vec!["stun:relay.ghostlink.example:3478".to_owned()];
        cfg.turn_urls = vec![
            "turn:relay.ghostlink.example:3478?transport=udp".to_owned(),
            "turns:relay.ghostlink.example:443?transport=tcp".to_owned(),
        ];
        let cfg = cfg
            .with_turn_secret("super-secret-zero-log-coturn-hmac-key")
            .expect("valid secret");

        let now_unix = 1_794_800_000;
        let ice = mint_ice_bootstrap(&cfg, now_unix);
        let turn = ice.turn.expect("turn credentials minted");
        assert_eq!(turn.ttl_secs, 300);

        assert!(verify_coturn_credential(
            cfg.turn_shared_secret_bytes().unwrap(),
            &turn.username,
            &turn.credential,
            now_unix + 299,
        ));
        assert!(!verify_coturn_credential(
            cfg.turn_shared_secret_bytes().unwrap(),
            &turn.username,
            &turn.credential,
            now_unix + 301,
        ));

        // Blinded rate limiter groups addresses from the same /64 IPv6 subscriber prefix
        let limiter = BlindedIpRateLimiter::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        let ip_a = IpAddr::V6("2001:db8:abcd:1234::1".parse::<Ipv6Addr>().unwrap());
        let ip_b = IpAddr::V6("2001:db8:abcd:1234::9999".parse::<Ipv6Addr>().unwrap());

        assert!(limiter.check_and_consume(ip_a, 1, t0));
        assert!(limiter.check_and_consume(ip_b, 1, t0));
        // 3rd request from another interface ID inside the SAME /64 prefix is throttled!
        assert!(!limiter.check_and_consume(ip_b, 1, t0));
    }
}
