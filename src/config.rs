use std::{net::SocketAddr, path::PathBuf};

use axum::http::Uri;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "A low-latency, JSONL-logging proxy for an OpenAI-compatible HTTP API"
)]
pub struct Args {
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

    /// JSONL output file. Use '-' for stdout.
    #[arg(long, env = "LOG_FILE", default_value = "-")]
    pub log_file: PathBuf,
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

    #[test]
    fn defaults_are_valid() {
        let args = Args::try_parse_from(["proxy"]).unwrap();

        assert_eq!(args.listen_addr, "127.0.0.1:3000".parse().unwrap());
        assert_eq!(args.upstream_url, "http://127.0.0.1:1234");
        assert_eq!(args.connect_timeout_ms, 5_000);
        assert_eq!(args.log_file, PathBuf::from("-"));
    }

    #[test]
    fn accepts_an_upstream_path_prefix() {
        let args =
            Args::try_parse_from(["proxy", "--upstream-url", "http://127.0.0.1:1234/internal"])
                .unwrap();

        assert_eq!(args.upstream_url.path(), "/internal");
    }

    #[test]
    fn rejects_unsupported_or_relative_upstreams() {
        assert!(Args::try_parse_from(["proxy", "--upstream-url", "https://example.com"]).is_err());
        assert!(Args::try_parse_from(["proxy", "--upstream-url", "/relative"]).is_err());
        assert!(
            Args::try_parse_from(["proxy", "--upstream-url", "http://example.com?q=1"]).is_err()
        );
        assert!(
            Args::try_parse_from(["proxy", "--upstream-url", "http://user:pass@example.com"])
                .is_err()
        );
        assert!(Args::try_parse_from(["proxy", "--connect-timeout-ms", "0"]).is_err());
    }
}
