// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

//! The slice of GitHub's REST API that argo-cd's GitHub App credentials use.
//!
//! argo-cd is given GitHub App credentials whose enterprise base URL points
//! here, with the repository folded into the path:
//!
//! ```text
//! githubAppEnterpriseBaseUrl: http://127.0.0.1:8181/OWNER/REPO
//! ```
//!
//! so the token request it makes arrives as
//! `POST /OWNER/REPO/app/installations/ID/access_tokens` and is answered with a
//! token from idcat. The JWT argo-cd signs for the request is ignored, as is the
//! installation ID: the private key behind them is a throwaway, and idcat
//! decides which installation and permissions apply.

use crate::idcat::TokenSource;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::warn;

struct AppState<T> {
    tokens: T,
    token_lifetime: Duration,
}

pub fn token_router<T: TokenSource>(tokens: T, token_lifetime: Duration) -> Router {
    Router::new()
        .route(
            "/{owner}/{repo}/app/installations/{installation_id}/access_tokens",
            post(repo_token::<T>),
        )
        .with_state(Arc::new(AppState {
            tokens,
            token_lifetime,
        }))
}

pub fn health_router() -> Router {
    Router::new().route(
        "/healthz",
        get(|| async { Json(json!({ "status": "ok" })) }),
    )
}

async fn repo_token<T: TokenSource>(
    State(state): State<Arc<AppState<T>>>,
    Path((owner, repo, _installation_id)): Path<(String, String, u64)>,
) -> Response {
    token_response(&state, &owner, &repo).await
}

async fn token_response<T: TokenSource>(state: &AppState<T>, owner: &str, repo: &str) -> Response {
    if !is_valid_owner(owner) || !is_valid_repo(repo) {
        return github_error(StatusCode::NOT_FOUND, "Not Found");
    }
    match state.tokens.installation_token(owner, repo).await {
        Ok(token) => {
            let expires_at = SystemTime::now() + state.token_lifetime;
            let body = json!({
                "token": token,
                "expires_at": humantime::format_rfc3339_seconds(expires_at).to_string(),
            });
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(error) => {
            warn!(%error, "failed to obtain installation token");
            github_error(StatusCode::BAD_GATEWAY, &error.to_string())
        }
    }
}

fn github_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "message": message }))).into_response()
}

/// GitHub's rules: alphanumerics and hyphens, not starting with a hyphen.
fn is_valid_owner(owner: &str) -> bool {
    (1..=39).contains(&owner.len())
        && !owner.starts_with('-')
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// GitHub's rules: alphanumerics, dots, hyphens and underscores, but not . or ..
fn is_valid_repo(repo: &str) -> bool {
    (1..=100).contains(&repo.len())
        && repo != "."
        && repo != ".."
        && repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idcat::IdcatError;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct FakeTokens {
        requests: Mutex<Vec<(String, String)>>,
        error: Option<&'static str>,
    }

    impl TokenSource for Arc<FakeTokens> {
        async fn installation_token(&self, owner: &str, repo: &str) -> Result<String, IdcatError> {
            self.requests
                .lock()
                .unwrap()
                .push((owner.to_string(), repo.to_string()));
            match self.error {
                Some(error) => Err(IdcatError(error.to_string())),
                None => Ok("ghs_token".to_string()),
            }
        }
    }

    async fn request(
        router: Router,
        method: Method,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn router(tokens: &Arc<FakeTokens>) -> Router {
        token_router(tokens.clone(), Duration::from_secs(540))
    }

    fn requests(tokens: &FakeTokens) -> Vec<(String, String)> {
        tokens.requests.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn repo_token_has_github_shape() {
        let tokens = Arc::new(FakeTokens::default());
        let before = SystemTime::now();

        let (status, body) = request(
            router(&tokens),
            Method::POST,
            "/platfrom-cloud/manifests/app/installations/1/access_tokens",
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["token"], "ghs_token");
        let expires_at = humantime::parse_rfc3339(body["expires_at"].as_str().unwrap()).unwrap();
        assert!(expires_at > before + Duration::from_secs(530));
        assert!(expires_at <= SystemTime::now() + Duration::from_secs(540));
        assert_eq!(
            requests(&tokens),
            vec![("platfrom-cloud".to_string(), "manifests".to_string())]
        );
    }

    #[tokio::test]
    async fn rejects_paths_that_are_not_a_repo() {
        for (path, expected) in [
            (
                "/-bad/manifests/app/installations/1/access_tokens",
                StatusCode::NOT_FOUND,
            ),
            (
                "/platfrom-cloud/app/installations/1/access_tokens",
                StatusCode::NOT_FOUND,
            ),
            (
                "/platfrom-cloud/../app/installations/1/access_tokens",
                StatusCode::NOT_FOUND,
            ),
            (
                "/platfrom-cloud/a%3Fb/app/installations/1/access_tokens",
                StatusCode::NOT_FOUND,
            ),
            (
                "/platfrom-cloud/manifests/extra/app/installations/1/access_tokens",
                StatusCode::NOT_FOUND,
            ),
            (
                "/platfrom-cloud/manifests/app/installations/x/access_tokens",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let tokens = Arc::new(FakeTokens::default());

            let (status, _) = request(router(&tokens), Method::POST, path).await;

            assert_eq!(status, expected, "{path}");
            assert!(requests(&tokens).is_empty(), "{path}");
        }
    }

    #[tokio::test]
    async fn only_post_is_served() {
        let tokens = Arc::new(FakeTokens::default());

        let (status, _) = request(
            router(&tokens),
            Method::GET,
            "/platfrom-cloud/manifests/app/installations/1/access_tokens",
        )
        .await;

        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn idcat_failure_is_a_bad_gateway() {
        let tokens = Arc::new(FakeTokens {
            error: Some("idcat returned HTTP 403"),
            ..Default::default()
        });

        let (status, body) = request(
            router(&tokens),
            Method::POST,
            "/platfrom-cloud/manifests/app/installations/1/access_tokens",
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, json!({ "message": "idcat returned HTTP 403" }));
    }

    #[tokio::test]
    async fn health_is_on_its_own_router() {
        let tokens = Arc::new(FakeTokens::default());

        let (health, body) = request(health_router(), Method::GET, "/healthz").await;
        let (on_token_router, _) = request(router(&tokens), Method::GET, "/healthz").await;
        let (token_on_health_router, _) = request(
            health_router(),
            Method::POST,
            "/platfrom-cloud/manifests/app/installations/1/access_tokens",
        )
        .await;

        assert_eq!(health, StatusCode::OK);
        assert_eq!(body, json!({ "status": "ok" }));
        assert_eq!(on_token_router, StatusCode::NOT_FOUND);
        assert_eq!(token_on_health_router, StatusCode::NOT_FOUND);
    }
}
