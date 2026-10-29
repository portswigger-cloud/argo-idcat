// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

use crate::bearer::BearerSource;
use std::future::Future;
use std::time::Duration;
use tracing::info;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct IdcatError(pub(crate) String);

pub trait TokenSource: Send + Sync + 'static {
    /// A token for owner/repo, or an owner-wide one when repo is None.
    fn installation_token(
        &self,
        owner: &str,
        repo: Option<&str>,
    ) -> impl Future<Output = Result<String, IdcatError>> + Send;
}

/// Exchanges the bearer token, the pod's identity, for an installation token.
pub struct IdcatClient<B> {
    endpoint: String,
    github_app: String,
    bearer: B,
    http: reqwest::Client,
}

impl<B: BearerSource> IdcatClient<B> {
    pub fn new(endpoint: &str, github_app: &str, bearer: B) -> anyhow::Result<Self> {
        // reqwest is built without a crypto provider (see Cargo.toml) and
        // panics if none is installed. Fails harmlessly if one already is.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            github_app: github_app.to_string(),
            bearer,
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()?,
        })
    }
}

impl<B: BearerSource> TokenSource for IdcatClient<B> {
    async fn installation_token(
        &self,
        owner: &str,
        repo: Option<&str>,
    ) -> Result<String, IdcatError> {
        let target = match repo {
            Some(repo) => format!("{owner}/{repo}"),
            None => owner.to_string(),
        };
        let url = format!(
            "{}/installation-token/{}/{target}",
            self.endpoint, self.github_app
        );
        let bearer = self.bearer.bearer().await?;
        let response = self
            .http
            .post(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|e| IdcatError(format!("request to idcat failed: {}", chain(&e))))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| IdcatError(format!("failed to read idcat response: {}", chain(&e))))?;
        if !status.is_success() {
            return Err(IdcatError(format!(
                "idcat returned HTTP {} for {target}: {}",
                status.as_u16(),
                body.trim()
            )));
        }
        let token = body.trim();
        if token.is_empty() {
            return Err(IdcatError(format!(
                "idcat returned an empty token for {target}"
            )));
        }
        info!(%target, "obtained installation token");
        Ok(token.to_string())
    }
}

/// The error and its causes: reqwest's own message omits why a request
/// failed, such as a refused connection or an untrusted certificate.
fn chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(String, String)>>>;

    /// A local idcat that records each request and answers with `status` and `body`.
    async fn fake_idcat(status: StatusCode, body: &'static str) -> (String, Seen) {
        let seen: Seen = Arc::default();
        let recorder = seen.clone();
        let app = Router::new().fallback(post(move |uri: Uri, headers: HeaderMap| {
            let recorder = recorder.clone();
            async move {
                let auth = headers["authorization"].to_str().unwrap().to_string();
                recorder
                    .lock()
                    .unwrap()
                    .push((uri.path().to_string(), auth));
                (status, body)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/"), seen)
    }

    /// Hands out each of its bearer tokens in turn.
    struct FakeBearer(Mutex<Vec<Result<&'static str, &'static str>>>);

    impl BearerSource for FakeBearer {
        async fn bearer(&self) -> Result<String, IdcatError> {
            match self.0.lock().unwrap().remove(0) {
                Ok(token) => Ok(token.to_string()),
                Err(error) => Err(IdcatError(error.to_string())),
            }
        }
    }

    fn client(
        endpoint: &str,
        bearers: Vec<Result<&'static str, &'static str>>,
    ) -> IdcatClient<FakeBearer> {
        IdcatClient::new(endpoint, "argocd", FakeBearer(Mutex::new(bearers))).unwrap()
    }

    #[tokio::test]
    async fn repo_and_owner_tokens() {
        let (endpoint, seen) = fake_idcat(StatusCode::OK, "ghs_token\n").await;
        let client = client(&endpoint, vec![Ok("jwt"), Ok("refreshed")]);

        let repo_token = client
            .installation_token("platfrom-cloud", Some("manifests"))
            .await
            .unwrap();
        client
            .installation_token("platfrom-cloud", None)
            .await
            .unwrap();

        assert_eq!(repo_token, "ghs_token");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                (
                    "/installation-token/argocd/platfrom-cloud/manifests".to_string(),
                    "Bearer jwt".to_string()
                ),
                (
                    "/installation-token/argocd/platfrom-cloud".to_string(),
                    "Bearer refreshed".to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn error_status() {
        let (endpoint, _) = fake_idcat(StatusCode::FORBIDDEN, "forbidden").await;

        let error = client(&endpoint, vec![Ok("jwt")])
            .installation_token("o", Some("r"))
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "idcat returned HTTP 403 for o/r: forbidden"
        );
    }

    #[tokio::test]
    async fn empty_token() {
        let (endpoint, _) = fake_idcat(StatusCode::OK, "\n").await;

        let error = client(&endpoint, vec![Ok("jwt")])
            .installation_token("o", Some("r"))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("empty token"), "{error}");
    }

    #[tokio::test]
    async fn connection_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let error = client(&endpoint, vec![Ok("jwt")])
            .installation_token("o", Some("r"))
            .await
            .unwrap_err();

        assert!(
            error.to_string().starts_with("request to idcat failed"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn bearer_failure_is_returned_without_asking_idcat() {
        let (endpoint, seen) = fake_idcat(StatusCode::OK, "ghs_token").await;

        let error = client(
            &endpoint,
            vec![Err("STS GetWebIdentityToken failed: AccessDenied: no")],
        )
        .installation_token("o", Some("r"))
        .await
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "STS GetWebIdentityToken failed: AccessDenied: no"
        );
        assert!(seen.lock().unwrap().is_empty());
    }
}
