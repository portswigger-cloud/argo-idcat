// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

mod app;
mod bearer;
mod config;
mod idcat;
mod sts;

use crate::bearer::CachedBearer;
use crate::config::{BIND_ADDRESS, Config, HEALTH_BIND_ADDRESS, TOKEN_LIFETIME};
use crate::idcat::IdcatClient;
use crate::sts::StsIssuer;
use clap::Parser;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::trace::{self, TraceLayer};
use tracing::{Level, error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Configured through the environment: IDCAT_ENDPOINT is the base URL of
/// idcat and GITHUB_APP the idcat GitHub App to request tokens from.
/// AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN are the projected service
/// account token and the source role it is exchanged for, IDCAT_ROLE_ARN the
/// central role assumed from there, and AWS_REGION the STS region.
#[derive(Parser)]
struct Cli {
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log_filter = if cli.debug {
        "argo_idcat=debug,tower_http=debug"
    } else {
        "argo_idcat=info,tower_http=info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(tracing_subscriber::fmt::layer().json().with_ansi(false))
        .init();

    if let Err(error) = run().await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let config = Config::from_env()?;

    info!(
        version = VERSION,
        idcat_endpoint = %config.idcat_endpoint,
        github_app = %config.github_app,
        aws_region = %config.aws_region,
        source_role = %config.source_role_arn,
        idcat_role = %config.idcat_role_arn,
        "starting argo-idcat"
    );

    let bearer = CachedBearer::new(StsIssuer::new(&config).await);
    let client = IdcatClient::new(&config.idcat_endpoint, &config.github_app, bearer)?;
    let tokens = app::token_router(client, TOKEN_LIFETIME).layer(
        TraceLayer::new_for_http()
            .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
            .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
    );
    // Not traced: kubelet probes it every few seconds.
    let health = app::health_router();

    let token_listener = bind(BIND_ADDRESS, "token").await?;
    let health_listener = bind(HEALTH_BIND_ADDRESS, "health").await?;

    tokio::select! {
        result = axum::serve(token_listener, tokens) => result?,
        result = axum::serve(health_listener, health) => result?,
        signal = termination_signal() => {
            let signal = signal?;
            info!(signal, "caught signal, exiting");
        }
    }

    Ok(())
}

async fn bind(address: SocketAddr, name: &'static str) -> anyhow::Result<TcpListener> {
    let listener = TcpListener::bind(address)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {name} listener to {address}: {e}"))?;
    info!(%address, listener = name, "listening");
    Ok(listener)
}

#[cfg(unix)]
async fn termination_signal() -> anyhow::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = sigterm.recv() => Ok("SIGTERM"),
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok("SIGINT")
        }
    }
}

#[cfg(not(unix))]
async fn termination_signal() -> anyhow::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("SIGINT")
}
