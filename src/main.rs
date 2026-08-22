use std::{error::Error, path::Path, process::ExitCode, sync::Arc, time::Duration};

use axum::serve::ListenerExt;
use clap::Parser;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use mistralrs_proxy::{
    auth::KeyStore,
    config::{Cli, Command, KeyCommand, ServeArgs},
    logging, logs, manage, proxy,
    runtime::{self, BackendList, RuntimeConfig},
};

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(args),
        Command::Key(KeyCommand::Create { name, admin, keys }) => {
            manage::create(&keys.keys_file, &name, admin)
        }
        Command::Key(KeyCommand::Manage { keys }) => manage::manage(&keys.keys_file),
        Command::Logs(args) => logs::run(&args.log_file, args.summary),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mistralrs_proxy: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serve(args: ServeArgs) -> Result<(), Box<dyn Error>> {
    let keys = load_keys(&args.keys.keys_file)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args, keys))
}

fn load_keys(path: &Path) -> Result<KeyStore, Box<dyn Error>> {
    match KeyStore::from_file(path) {
        Ok(keys) => Ok(keys),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "no key file at {}. Run `mistralrs_proxy key create <name>` to create one.",
            path.display()
        )
        .into()),
        Err(error) => Err(error.into()),
    }
}

async fn run(args: ServeArgs, keys: KeyStore) -> Result<(), Box<dyn Error>> {
    let runtime_config = RuntimeConfig::load(&args.runtime_file).await?;
    let backends = BackendList::from_config(runtime_config);
    let initial_backend = backends.configured();

    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    let local_addr = listener.local_addr()?;
    let listener = listener.tap_io(|stream| {
        if let Err(error) = stream.set_nodelay(true) {
            eprintln!("could not enable TCP_NODELAY for a client connection: {error}");
        }
    });

    let (logger, log_worker) = logging::start(&args.log_file, !args.quiet)?;
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_millis(args.connect_timeout_ms)));
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let key_count = keys.len();
    let app = proxy::router(Arc::new(proxy::AppState::new(
        client,
        backends.clone(),
        logger,
        keys,
    )));
    let reload_task = tokio::spawn(runtime::reload(args.runtime_file.clone(), backends));

    eprintln!(
        "proxy listening on http://{local_addr}, runtime config {}, backend {} at {} is {}, {key_count} key{} loaded",
        args.runtime_file.display(),
        initial_backend.id,
        initial_backend.url,
        if initial_backend.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if key_count == 1 { "" } else { "s" },
    );
    let serve_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    reload_task.abort();
    let reload_result = reload_task.await;

    // Dropping the service closes the event channel. The worker drains
    // everything already queued before it exits and flushes the JSONL writer.
    let log_result = log_worker.join();
    serve_result?;
    if let Err(error) = reload_result
        && !error.is_cancelled()
    {
        return Err(format!("runtime config reloader stopped: {error}").into());
    }
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
