use std::{error::Error, sync::Arc, time::Duration};

use axum::serve::ListenerExt;
use clap::Parser;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{config::Args, logging, proxy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    let local_addr = listener.local_addr()?;
    let listener = listener.tap_io(|stream| {
        if let Err(error) = stream.set_nodelay(true) {
            eprintln!("could not enable TCP_NODELAY for a client connection: {error}");
        }
    });

    let (logger, log_worker) = logging::start(&args.log_file)?;
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_millis(args.connect_timeout_ms)));
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let app = proxy::router(Arc::new(proxy::AppState::new(
        client,
        args.upstream_url,
        logger,
    )));

    eprintln!("proxy listening on http://{local_addr}");
    let serve_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;

    // Dropping the service closes the event channel. The worker drains everything
    // already queued before it exits and flushes the JSONL writer.
    let log_result = log_worker.join();
    serve_result?;
    log_result?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("could not install SIGTERM handler: {error}");
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            result = ctrl_c => {
                if let Err(error) = result {
                    eprintln!("could not install Ctrl-C handler: {error}");
                }
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = ctrl_c.await {
        eprintln!("could not install Ctrl-C handler: {error}");
    }
}
