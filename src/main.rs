use std::{
    error::Error,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use axum::{Extension, Router, extract::ConnectInfo};
use clap::Parser;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
    service::TowerToHyperService,
};
use mistralrs_proxy::{
    auth::KeyStore,
    backend_cli,
    backend_state::BackendStateStore,
    config::{Cli, Command, KeyCommand, ServeArgs},
    control::{ControlState, UdsPeer, bind_control_socket},
    logging, logs, manage, proxy,
    routing::{RoutingState, run_readiness_worker, run_telemetry_worker},
    runtime::{RuntimeConfig, RuntimeState},
};
use tokio::{sync::watch, task::JoinSet};

const SERVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const AUDIT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(args),
        Command::Key(KeyCommand::Create { name, admin, keys }) => {
            manage::create(&keys.keys_file, &name, admin)
        }
        Command::Key(KeyCommand::Manage { keys }) => manage::manage(&keys.keys_file),
        Command::Backend(command) => backend_cli::run(command),
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
    let runtime = RuntimeState::from_config(runtime_config);
    let backend_state = BackendStateStore::load(args.backend_state_file.clone())?;
    runtime.restore_modes(&backend_state.modes());

    let listener = tokio::net::TcpListener::bind(args.listen_addr).await?;
    let local_addr = listener.local_addr()?;

    #[cfg(unix)]
    let control_listener = bind_control_socket(&args.control.control_socket).await?;
    #[cfg(unix)]
    let _control_socket_guard = OwnedControlSocket::new(args.control.control_socket.clone())?;

    // Request records live only in the JSONL audit log. `serve` emits a small
    // number of lifecycle and state-transition lines of its own.
    let (logger, log_worker) = logging::start(&args.log_file, false)?;
    let log_health = logger.health();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_millis(args.connect_timeout_ms)));
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let key_count = keys.len();
    let routing = RoutingState::new(runtime.clone());
    let app = proxy::router(Arc::new(proxy::AppState::with_routing(
        client.clone(),
        runtime.clone(),
        routing.clone(),
        logger,
        keys,
    )));

    let operational_quiet = args.quiet || args.log_file == Path::new("-");
    let control = Arc::new(ControlState::new(
        runtime.clone(),
        routing.clone(),
        backend_state,
        args.runtime_file.clone(),
        operational_quiet,
    ));
    control.resume_persisted_drains();

    let mut telemetry_task = tokio::spawn(run_telemetry_worker(
        client.clone(),
        runtime.clone(),
        routing.clone(),
        operational_quiet,
    ));
    let mut readiness_task = tokio::spawn(run_readiness_worker(
        client,
        runtime.clone(),
        routing,
        operational_quiet,
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut public_task = tokio::spawn(serve_public(
        listener,
        app,
        shutdown_rx.clone(),
        operational_quiet,
    ));

    #[cfg(unix)]
    let mut control_task = tokio::spawn(serve_control(
        control_listener,
        control.router(),
        shutdown_rx,
        operational_quiet,
    ));

    if !operational_quiet {
        println!(
            "INFO proxy listening on http://{local_addr}; control {}; runtime {} revision {}; {} backend{}; {key_count} key{}; audit log {}",
            args.control.control_socket.display(),
            args.runtime_file.display(),
            runtime.revision(),
            runtime.backends().len(),
            if runtime.backends().len() == 1 {
                ""
            } else {
                "s"
            },
            if key_count == 1 { "" } else { "s" },
            args.log_file.display(),
        );
    }

    enum Stopped {
        Signal,
        Public(Result<Result<(), std::io::Error>, tokio::task::JoinError>),
        #[cfg(unix)]
        Control(Result<Result<(), std::io::Error>, tokio::task::JoinError>),
        Telemetry(Result<Result<(), String>, tokio::task::JoinError>),
        Readiness(Result<Result<(), String>, tokio::task::JoinError>),
        Logger,
    }

    #[cfg(unix)]
    let stopped = tokio::select! {
        _ = shutdown_signal() => Stopped::Signal,
        result = &mut public_task => Stopped::Public(result),
        result = &mut control_task => Stopped::Control(result),
        result = &mut telemetry_task => Stopped::Telemetry(result),
        result = &mut readiness_task => Stopped::Readiness(result),
        _ = log_health.wait_until_unhealthy() => Stopped::Logger,
    };
    #[cfg(not(unix))]
    let stopped = tokio::select! {
        _ = shutdown_signal() => Stopped::Signal,
        result = &mut public_task => Stopped::Public(result),
        result = &mut telemetry_task => Stopped::Telemetry(result),
        result = &mut readiness_task => Stopped::Readiness(result),
        _ = log_health.wait_until_unhealthy() => Stopped::Logger,
    };
    let telemetry_stopped = matches!(&stopped, Stopped::Telemetry(_));
    let readiness_stopped = matches!(&stopped, Stopped::Readiness(_));
    let _ = shutdown_tx.send(true);

    // Do not use `?` while assembling this result: all background workers and
    // the audit writer must be shut down and flushed even when a server task
    // failed.
    let serve_result: Result<(), Box<dyn Error>> = match stopped {
        Stopped::Signal => {
            let public = shutdown_server_task(&mut public_task, "public", operational_quiet).await;
            #[cfg(unix)]
            let control =
                shutdown_server_task(&mut control_task, "control", operational_quiet).await;
            #[cfg(unix)]
            {
                public.and(control)
            }
            #[cfg(not(unix))]
            public
        }
        Stopped::Public(result) => {
            let public = flatten_server_result(result);
            #[cfg(unix)]
            let control =
                shutdown_server_task(&mut control_task, "control", operational_quiet).await;
            #[cfg(unix)]
            {
                public.and(control)
            }
            #[cfg(not(unix))]
            public
        }
        #[cfg(unix)]
        Stopped::Control(result) => {
            let control = flatten_server_result(result);
            let public = shutdown_server_task(&mut public_task, "public", operational_quiet).await;
            control.and(public)
        }
        Stopped::Telemetry(result) => {
            let worker = unexpected_worker_stop("telemetry", result);
            let public = shutdown_server_task(&mut public_task, "public", operational_quiet).await;
            #[cfg(unix)]
            let control =
                shutdown_server_task(&mut control_task, "control", operational_quiet).await;
            #[cfg(unix)]
            {
                worker.and(public).and(control)
            }
            #[cfg(not(unix))]
            worker.and(public)
        }
        Stopped::Readiness(result) => {
            let worker = unexpected_worker_stop("readiness", result);
            let public = shutdown_server_task(&mut public_task, "public", operational_quiet).await;
            #[cfg(unix)]
            let control =
                shutdown_server_task(&mut control_task, "control", operational_quiet).await;
            #[cfg(unix)]
            {
                worker.and(public).and(control)
            }
            #[cfg(not(unix))]
            worker.and(public)
        }
        Stopped::Logger => {
            let logger: Result<(), Box<dyn Error>> =
                Err("audit log writer stopped; refusing to continue serving".into());
            let public = shutdown_server_task(&mut public_task, "public", operational_quiet).await;
            #[cfg(unix)]
            let control =
                shutdown_server_task(&mut control_task, "control", operational_quiet).await;
            #[cfg(unix)]
            {
                logger.and(public).and(control)
            }
            #[cfg(not(unix))]
            logger.and(public)
        }
    };

    if !telemetry_stopped {
        telemetry_task.abort();
        let _ = telemetry_task.await;
    }
    if !readiness_stopped {
        readiness_task.abort();
        let _ = readiness_task.await;
    }

    // Dropping the service closes the event channel. The worker drains
    // everything already queued before it exits and flushes the JSONL writer.
    let log_result =
        tokio::task::spawn_blocking(move || log_worker.join_timeout(AUDIT_SHUTDOWN_GRACE))
            .await
            .map_err(|error| std::io::Error::other(format!("audit join task failed: {error}")))
            .and_then(|result| result);
    if let Err(error) = &log_result {
        eprintln!("WARN audit log did not shut down cleanly: {error}");
    }
    serve_result?;
    log_result?;

    if !operational_quiet {
        println!("INFO proxy stopped");
    }

    Ok(())
}

async fn serve_public(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) -> std::io::Result<()> {
    let mut connections = JoinSet::new();
    let stop_accepting = wait_for_shutdown(shutdown.clone());
    tokio::pin!(stop_accepting);

    loop {
        tokio::select! {
            _ = &mut stop_accepting => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        abort_connections(&mut connections).await;
                        return Err(error);
                    }
                };
                if let Err(error) = stream.set_nodelay(true)
                    && !quiet
                {
                    eprintln!("WARN could not enable TCP_NODELAY for {peer}: {error}");
                }
                let service = app.clone().layer(Extension(ConnectInfo(peer)));
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let builder = ServerBuilder::new(TokioExecutor::new());
                    let connection = builder
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            TowerToHyperService::new(service),
                        );
                    tokio::pin!(connection);
                    let graceful = wait_for_shutdown(connection_shutdown);
                    tokio::pin!(graceful);
                    tokio::select! {
                        // Connection resets and malformed client traffic are
                        // local and do not take down the listener.
                        _ = &mut connection => {}
                        _ = &mut graceful => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    abort_connections(&mut connections).await;
                    return Err(std::io::Error::other(format!(
                        "public connection task failed: {error}"
                    )));
                }
            }
        }
    }

    drain_connections(&mut connections, "public", quiet).await
}

#[cfg(unix)]
async fn serve_control(
    listener: tokio::net::UnixListener,
    app: Router,
    shutdown: watch::Receiver<bool>,
    quiet: bool,
) -> std::io::Result<()> {
    let mut connections = JoinSet::new();
    let stop_accepting = wait_for_shutdown(shutdown.clone());
    tokio::pin!(stop_accepting);

    loop {
        tokio::select! {
            _ = &mut stop_accepting => break,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        abort_connections(&mut connections).await;
                        return Err(error);
                    }
                };
                let service = app
                    .clone()
                    .layer(Extension(ConnectInfo(UdsPeer::from_stream(&stream))));
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let builder = ServerBuilder::new(TokioExecutor::new());
                    let connection = builder
                        .serve_connection_with_upgrades(
                            TokioIo::new(stream),
                            TowerToHyperService::new(service),
                        );
                    tokio::pin!(connection);
                    let graceful = wait_for_shutdown(connection_shutdown);
                    tokio::pin!(graceful);
                    tokio::select! {
                        _ = &mut connection => {}
                        _ = &mut graceful => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    abort_connections(&mut connections).await;
                    return Err(std::io::Error::other(format!(
                        "control connection task failed: {error}"
                    )));
                }
            }
        }
    }

    drain_connections(&mut connections, "control", quiet).await
}

async fn drain_connections(
    connections: &mut JoinSet<()>,
    server: &str,
    quiet: bool,
) -> std::io::Result<()> {
    drain_connections_with_grace(connections, server, quiet, SERVER_SHUTDOWN_GRACE).await
}

async fn drain_connections_with_grace(
    connections: &mut JoinSet<()>,
    server: &str,
    quiet: bool,
    shutdown_grace: Duration,
) -> std::io::Result<()> {
    if connections.is_empty() {
        return Ok(());
    }

    let grace = tokio::time::sleep(shutdown_grace);
    tokio::pin!(grace);
    loop {
        tokio::select! {
            result = connections.join_next() => match result {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    let error = std::io::Error::other(format!(
                        "{server} connection task failed during shutdown: {error}"
                    ));
                    abort_connections(connections).await;
                    return Err(error);
                }
                None => return Ok(()),
            },
            _ = &mut grace => {
                let remaining = connections.len();
                if !quiet {
                    eprintln!(
                        "WARN {server} server exceeded the {}s shutdown grace; aborting {remaining} remaining connection{}",
                        shutdown_grace.as_secs_f64(),
                        if remaining == 1 { "" } else { "s" },
                    );
                }
                abort_connections(connections).await;
                return Ok(());
            }
        }
    }
}

async fn abort_connections(connections: &mut JoinSet<()>) {
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

fn flatten_server_result(
    result: Result<Result<(), std::io::Error>, tokio::task::JoinError>,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(result) => Ok(result?),
        Err(error) => Err(format!("server task stopped unexpectedly: {error}").into()),
    }
}

async fn shutdown_server_task(
    task: &mut tokio::task::JoinHandle<Result<(), std::io::Error>>,
    _name: &str,
    _quiet: bool,
) -> Result<(), Box<dyn Error>> {
    flatten_server_result(task.await)
}

fn unexpected_worker_stop(
    name: &str,
    result: Result<Result<(), String>, tokio::task::JoinError>,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(Ok(())) => Err(format!("{name} worker stopped unexpectedly").into()),
        Ok(Err(error)) => Err(format!("{name} worker failed: {error}").into()),
        Err(error) => Err(format!("{name} worker failed: {error}").into()),
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

#[cfg(unix)]
struct OwnedControlSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl OwnedControlSocket {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(unix)]
impl Drop for OwnedControlSocket {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn socket_path() -> PathBuf {
        // macOS Unix-domain socket paths are limited to roughly 104 bytes and
        // `$TMPDIR` is already long. Eight UUID characters are ample for this
        // process-local test while keeping the path comfortably below SUN_LEN.
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        std::env::temp_dir().join(format!("mp-{}.sock", &suffix[..8]))
    }

    #[test]
    fn control_socket_guard_removes_only_the_socket_it_owns() {
        let path = socket_path();
        let first = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let guard = OwnedControlSocket::new(path.clone()).unwrap();

        drop(first);
        std::fs::remove_file(&path).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(guard);

        assert!(path.exists(), "replacement socket was unlinked");
        drop(replacement);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn public_server_gracefully_closes_an_idle_keep_alive_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let (shutdown, receiver) = watch::channel(false);
        let server = tokio::spawn(serve_public(listener, app, receiver, true));

        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0_u8; 512];
        let bytes = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..bytes]).contains("200 OK"));

        shutdown.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("idle keep-alive connection ignored graceful shutdown")
            .unwrap()
            .unwrap();
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn shutdown_deadline_aborts_owned_connection_tasks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut connections = JoinSet::new();
        let task_flag = Arc::clone(&dropped);
        connections.spawn(async move {
            let _flag = DropFlag(task_flag);
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();

        drain_connections_with_grace(&mut connections, "test", true, Duration::from_millis(10))
            .await
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(connections.is_empty());
    }
}
