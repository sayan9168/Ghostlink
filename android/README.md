# Android host: local capture milestone

Requires JDK 17, Android SDK 35 and Gradle 8.9. No Gradle wrapper binary is
checked in. Install Gradle 8.9 or use the CI workflow's configured distribution.

```sh
cd android
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

This is **not yet a remote-control client**. It exercises explicit Android
MediaProjection approval, a visible mediaProjection foreground service, a Stop
notification, surface-input H.264 encoding, bounded encoder draining and cleanup.
Frames are discarded without disk or network output. The app requests no internet
or accessibility permission. No boot receiver, hidden capture, stored consent,
automatic reconnection or sticky restart exists.

Notifications must be allowed before starting capture. Each new capture requires
fresh system approval. Resizing/app-window sharing stops capture rather than
reusing a projection grant. Reopen the activity after a system-initiated stop if
its local UI still considers capture active, or tap Stop to reset the local gate.

## Device acceptance checks (not yet run)

- Android 10 and 14/15: cancel approval → no foreground capture.
- Approve → persistent notification + Android projection indicator visible.
- Stop in app / notification / system projection chip → capture ends.
- Rotate or resize → fail closed, fresh grant required for another capture.
- Kill/restart process → no resumed screen sharing.
- Deny notification permission → cannot initiate capture.
- Inspect app storage and network → no frames persisted or transmitted.

Next: replace the discard sink only after authenticated transport, host-side
per-session remote-peer approval, and bounded backpressure are implemented. Input
injection must stay disabled until a separate, explicit accessibility opt-in and
per-session authorization exist.
