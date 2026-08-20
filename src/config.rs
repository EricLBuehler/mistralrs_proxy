use std::{net::SocketAddr, path::PathBuf};

use axum::http::Uri;
use clap::{Args as ClapArgs, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "A low-latency proxy for an OpenAI-compatible HTTP API, with per-key access control and token accounting",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Serve(ServeArgs),
    /// Create and administer API keys.
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Issue a new API key and print it once.
    Create {
        /// Label recorded with the key, for logs and the manage view.
        name: String,

        /// Mark the key as an admin key. The first key in a new file is always
        /// an admin key.
        #[arg(long)]
        admin: bool,

        #[command(flatten)]
        keys: KeysFile,
    },
    /// Open the interactive key manager.
    Manage {
        #[command(flatten)]
        keys: KeysFile,
    },
}

#[derive(Debug, ClapArgs)]
pub struct KeysFile {
    /// JSON key database.
    #[arg(
        long,
        env = "KEYS_FILE",
        default_value = "keys.json",
        value_name = "PATH"
    )]
    pub keys_file: PathBuf,
}

#[derive(Debug, ClapArgs)]
pub struct ServeArgs {
    #[command(flatten)]
    pub keys: KeysFile,

    /// Address on which the proxy accepts connections.
    #[arg(
        short = 'l',
        long,
        env = "LISTEN_ADDR",
        default_value = "127.0.0.1:3000"
    )]
    pub listen_addr: SocketAddr,

    /// HTTP upstream origin (an optional path prefix is supported).
    #[arg(
        short = 'u',
        long,
        env = "UPSTREAM_URL",
        default_value = "http://127.0.0.1:1234",
        value_parser = parse_upstream_url
    )]
    pub upstream_url: Uri,

    /// Maximum time to establish a connection to the upstream.
    #[arg(
        long,
        env = "CONNECT_TIMEOUT_MS",
        default_value_t = 5_000,
        value_parser = clap::value_parser!(u64).range(1..),
        value_name = "MILLISECONDS"
    )]
    pub connect_timeout_ms: u64,

    /// JSONL audit log. Use '-' to write it to stdout instead.
    #[arg(long, env = "LOG_FILE", default_value = "proxy.jsonl")]
    pub log_file: PathBuf,

    /// Do not print per-request lines to stderr.
    #[arg(long, env = "QUIET")]
    pub quiet: bool,
}

fn parse_upstream_url(value: &str) -> Result<Uri, String> {
    let uri = value
        .parse::<Uri>()
        .map_err(|error| format!("invalid URI: {error}"))?;

    if uri.scheme_str() != Some("http") {
        return Err("upstream URL must use http:// (this build has no TLS connector)".to_owned());
    }
    let Some(authority) = uri.authority() else {
        return Err("upstream URL must include a host".to_owned());
    };
    if authority.as_str().contains('@') {
        return Err("upstream URL cannot include user information".to_owned());
    }
    if uri.query().is_some() {
        return Err("upstream URL cannot include a query string".to_owned());
    }

    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve(extra: &[&str]) -> Result<ServeArgs, clap::Error> {
        let arguments = ["mistralrs_proxy", "serve"]
            .into_iter()
            .chain(extra.iter().copied());
        match Cli::try_parse_from(arguments)?.command {
            Command::Serve(args) => Ok(args),
            other => panic!("expected serve, got {other:?}"),
        }
    }

    #[test]
    fn serve_defaults_are_valid() {
        let args = serve(&[]).unwrap();

        assert_eq!(args.keys.keys_file, PathBuf::from("keys.json"));
        assert_eq!(args.listen_addr, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(args.upstream_url, "http://127.0.0.1:1234");
        assert_eq!(args.connect_timeout_ms, 5_000);
        assert_eq!(args.log_file, PathBuf::from("proxy.jsonl"));
        assert!(!args.quiet);
    }

    #[test]
    fn accepts_an_upstream_path_prefix() {
        let args = serve(&["--upstream-url", "http://127.0.0.1:1234/internal"]).unwrap();

        assert_eq!(args.upstream_url.path(), "/internal");
    }

    #[test]
    fn rejects_unsupported_or_relative_upstreams() {
        assert!(serve(&["--upstream-url", "https://example.com"]).is_err());
        assert!(serve(&["--upstream-url", "/relative"]).is_err());
        assert!(serve(&["--upstream-url", "http://example.com?q=1"]).is_err());
        assert!(serve(&["--upstream-url", "http://user:pass@example.com"]).is_err());
        assert!(serve(&["--connect-timeout-ms", "0"]).is_err());
    }

    #[test]
    fn key_create_takes_a_name_and_an_admin_flag() {
        let cli =
            Cli::try_parse_from(["mistralrs_proxy", "key", "create", "alice", "--admin"]).unwrap();

        match cli.command {
            Command::Key(KeyCommand::Create { name, admin, keys }) => {
                assert_eq!(name, "alice");
                assert!(admin);
                assert_eq!(keys.keys_file, PathBuf::from("keys.json"));
            }
            other => panic!("expected key create, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["mistralrs_proxy", "key", "create"]).is_err());
    }

    #[test]
    fn key_manage_is_available() {
        let cli = Cli::try_parse_from([
            "mistralrs_proxy",
            "key",
            "manage",
            "--keys-file",
            "/tmp/other.json",
        ])
        .unwrap();

        match cli.command {
            Command::Key(KeyCommand::Manage { keys }) => {
                assert_eq!(keys.keys_file, PathBuf::from("/tmp/other.json"));
            }
            other => panic!("expected key manage, got {other:?}"),
        }
    }

    #[test]
    fn a_subcommand_is_required() {
        assert!(Cli::try_parse_from(["mistralrs_proxy"]).is_err());
    }
}
