//! Production zero-log binary entrypoint for `ghostlink-signal`.
//!
//! Intentionally emits zero access logs, room tokens, or client IP addresses to stdout/stderr.

use std::net::SocketAddr;
use std::process::ExitCode;

use ghostlink_signal::{
    build_router, spawn_reaper_task, SignalConfig, SignalState, DEFAULT_REAPER_INTERVAL,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match SignalConfig::from_env() {
        Ok(cfg) => cfg,
        Err(_) => return ExitCode::from(2),
    };

    let bind_addr = config.bind_addr;
    let state = match SignalState::new(config) {
        Ok(st) => st,
        Err(_) => return ExitCode::from(2),
    };

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(_) => return ExitCode::from(1),
    };

    let reaper = spawn_reaper_task(state.clone(), DEFAULT_REAPER_INTERVAL);
    let service = build_router(state).into_make_service_with_connect_info::<SocketAddr>();

    let serve_res = axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    reaper.abort();

    if serve_res.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
