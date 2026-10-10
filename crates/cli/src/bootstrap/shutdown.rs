use std::future::Future;

/// Registers for SIGTERM (`docker stop`, systemd) and SIGINT (Ctrl-C) at once, so a
/// signal that lands while the servers start is not lost. The future names the signal.
#[cfg(unix)]
pub fn shutdown_signal() -> std::io::Result<impl Future<Output = &'static str>> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => "SIGTERM",
            _ = interrupt.recv() => "SIGINT",
        }
    })
}

#[cfg(not(unix))]
pub fn shutdown_signal() -> std::io::Result<impl Future<Output = &'static str>> {
    Ok(async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
        "Ctrl-C"
    })
}
