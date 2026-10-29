// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

//! Identity tokens from AWS STS GetWebIdentityToken (IAM outbound identity
//! federation), signed with the central role's credentials. Those come from a
//! chain of two role assumptions: the pod's projected service account token
//! is exchanged for a source role in the cluster's own account
//! (AssumeRoleWithWebIdentity, as IRSA does), whose credentials then assume
//! the central role (AssumeRole). GetWebIdentityToken is not served by STS's
//! global endpoint, so every request goes to the region's.

use crate::bearer::{IdentityToken, TokenIssuer};
use crate::config::Config;
use crate::idcat::IdcatError;
use aws_config::SdkConfig;
use aws_config::provider_config::ProviderConfig;
use aws_config::sts::AssumeRoleProvider;
use aws_config::web_identity_token::{StaticConfiguration, WebIdentityTokenCredentialsProvider};
use aws_credential_types::provider::error::CredentialsError;
use aws_sdk_sts::config::{
    BehaviorVersion, Credentials, ProvideCredentials, Region, SharedAsyncSleep,
    SharedCredentialsProvider, SharedHttpClient, retry::RetryConfig, timeout::TimeoutConfig,
};
use aws_sdk_sts::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_sts::operation::assume_role::AssumeRoleError;
use aws_sdk_sts::operation::assume_role_with_web_identity::AssumeRoleWithWebIdentityError;
use aws_smithy_async::rt::sleep::TokioSleep;
use aws_smithy_async::time::SharedTimeSource;
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::info;

const SIGNING_ALGORITHM: &str = "ES384";
/// The longest token the IAM role may request.
const MAX_TOKEN_DURATION: Duration = Duration::from_secs(3600);
/// The shortest token STS issues.
const MIN_TOKEN_DURATION: Duration = Duration::from_secs(60);
/// The central role's credentials: an hour, the most STS allows a chained role
/// session. STS refuses a token that would outlive the credentials that signed
/// the request, so each token gets new credentials, and tokens come out an
/// hour less the leeway below and the time the requests took.
const CREDENTIALS_LIFETIME: Duration = Duration::from_secs(3600);
/// Kept between a token's expiry and its credentials', for clock differences.
const EXPIRY_LEEWAY: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The role session name of both assumptions, which is what CloudTrail shows.
const SESSION_NAME: &str = "argo-idcat";

pub struct StsIssuer {
    sts: aws_sdk_sts::Client,
    /// What the tokens are for: idcat's host, which the central role's IAM
    /// policy has to allow.
    audience: String,
    provider: SharedCredentialsProvider,
    /// For error messages: the providers' own don't name it.
    token_file: PathBuf,
}

impl StsIssuer {
    /// Credentials come from the projected service account token and the two
    /// roles in `config`, and nowhere else: not the SDK's default chain, which
    /// would fall back to the node's role.
    pub async fn new(config: &Config) -> Self {
        Self::build(config, https_client(), RetryConfig::standard()).await
    }

    async fn build(config: &Config, http: SharedHttpClient, retry: RetryConfig) -> Self {
        let region = Region::new(config.aws_region.clone());
        let timeout = TimeoutConfig::builder()
            .operation_attempt_timeout(REQUEST_TIMEOUT)
            .build();
        // Reads the token file on every call, so a token kubelet has rotated
        // is picked up the next time credentials are fetched.
        let source_role = WebIdentityTokenCredentialsProvider::builder()
            .configure(
                &ProviderConfig::without_region()
                    .with_region(Some(region.clone()))
                    .with_http_client(http.clone())
                    .with_retry_config(retry.clone())
                    .with_timeout_config(timeout.clone()),
            )
            .static_configuration(StaticConfiguration {
                web_identity_token_file: config.web_identity_token_file.clone(),
                role_arn: config.source_role_arn.clone(),
                session_name: SESSION_NAME.to_string(),
            })
            .build();
        // Doesn't cache: each call assumes the central role with new source
        // role credentials.
        let central_role = AssumeRoleProvider::builder(&config.idcat_role_arn)
            .session_name(SESSION_NAME)
            .session_length(CREDENTIALS_LIFETIME)
            .configure(
                &SdkConfig::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .region(region.clone())
                    .http_client(http.clone())
                    .sleep_impl(SharedAsyncSleep::new(TokioSleep::new()))
                    .time_source(SharedTimeSource::default())
                    .retry_config(retry.clone())
                    .timeout_config(timeout.clone())
                    .build(),
            )
            .build_from_provider(source_role)
            .await;
        Self {
            sts: aws_sdk_sts::Client::from_conf(
                aws_sdk_sts::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .region(region)
                    .http_client(http)
                    .retry_config(retry)
                    .timeout_config(timeout)
                    .build(),
            ),
            audience: config.audience().to_string(),
            provider: SharedCredentialsProvider::new(central_role),
            token_file: config.web_identity_token_file.clone(),
        }
    }

    /// New credentials for the central role. Not kept: a token is only as long
    /// as the credentials have left, and tokens are needed half-hourly.
    async fn credentials(&self) -> Result<Credentials, IdcatError> {
        let credentials = self
            .provider
            .provide_credentials()
            .await
            .map_err(|e| credentials_error(&e, &self.token_file))?;
        if let Some(expiry) = credentials.expiry() {
            info!(
                expiration = %humantime::format_rfc3339_seconds(expiry),
                "obtained AWS credentials"
            );
        }
        Ok(credentials)
    }
}

impl TokenIssuer for StsIssuer {
    async fn issue(&self) -> Result<IdentityToken, IdcatError> {
        let credentials = self.credentials().await?;
        let duration = token_duration(remaining(&credentials, SystemTime::now()));
        let output = self
            .sts
            .get_web_identity_token()
            .audience(&self.audience)
            .signing_algorithm(SIGNING_ALGORITHM)
            .duration_seconds(duration.as_secs() as i32)
            .customize()
            .config_override(aws_sdk_sts::Config::builder().credentials_provider(credentials))
            .send()
            .await
            .map_err(|e| sts_error("GetWebIdentityToken", &e))?;
        let token = output
            .web_identity_token()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| IdcatError("STS GetWebIdentityToken returned no token".into()))?;
        let expiration = output
            .expiration()
            .ok_or_else(|| IdcatError("STS GetWebIdentityToken returned no expiration".into()))?;
        let expiration = SystemTime::try_from(*expiration).map_err(|e| {
            IdcatError(format!(
                "STS GetWebIdentityToken returned a bad expiration: {e}"
            ))
        })?;
        Ok(IdentityToken {
            token: token.to_string(),
            expiration,
        })
    }
}

/// The SDK's default HTTPS client uses aws-lc-rs; this one uses ring.
fn https_client() -> SharedHttpClient {
    aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
        .build_https()
}

/// How long credentials have left. Ones without an expiry, which STS doesn't
/// hand out, count as long-lived.
fn remaining(credentials: &Credentials, now: SystemTime) -> Duration {
    match credentials.expiry() {
        Some(expiry) => expiry.duration_since(now).unwrap_or_default(),
        None => Duration::MAX,
    }
}

/// The longest token STS will issue with credentials that have `remaining`
/// left, up to what the IAM role allows.
fn token_duration(remaining: Duration) -> Duration {
    let seconds = remaining.saturating_sub(EXPIRY_LEEWAY).as_secs();
    Duration::from_secs(seconds).clamp(MIN_TOKEN_DURATION, MAX_TOKEN_DURATION)
}

/// Which step of fetching the central role's credentials failed, and why.
/// The errors nest: AssumeRole's failure to get the source role's credentials
/// wraps AssumeRoleWithWebIdentity's, which wraps the token file's, so the
/// innermost one is what went wrong.
fn credentials_error(error: &CredentialsError, token_file: &Path) -> IdcatError {
    let mut cause = None;
    let mut previous: Option<&(dyn Error + 'static)> = None;
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(e) = current {
        if let Some(e) = e.downcast_ref::<SdkError<AssumeRoleError>>() {
            cause = Some(sts_error("AssumeRole", e));
        } else if let Some(e) = e.downcast_ref::<SdkError<AssumeRoleWithWebIdentityError>>() {
            cause = Some(sts_error("AssumeRoleWithWebIdentity", e));
            break;
        } else if let Some(e) = e.downcast_ref::<std::io::Error>()
            // Not one from deep inside a failed connection.
            && previous.is_some_and(|p| p.is::<CredentialsError>())
        {
            cause = Some(IdcatError(format!(
                "failed to read the web identity token file {}: {e}",
                token_file.display()
            )));
            break;
        }
        previous = Some(e);
        current = e.source();
    }
    let cause = cause.map_or_else(
        || DisplayErrorContext(error).to_string(),
        |cause| cause.to_string(),
    );
    IdcatError(format!("failed to get AWS credentials: {cause}"))
}

/// STS's error code and message when it sent one, and the whole error chain,
/// such as a timeout or a refused connection, when it didn't.
fn sts_error<E, R>(operation: &str, error: &SdkError<E, R>) -> IdcatError
where
    E: ProvideErrorMetadata + Error + 'static,
    R: std::fmt::Debug,
{
    match (error.code(), error.message()) {
        (Some(code), Some(message)) => {
            IdcatError(format!("STS {operation} failed: {code}: {message}"))
        }
        (Some(code), None) => IdcatError(format!("STS {operation} failed: {code}")),
        _ => IdcatError(format!(
            "STS {operation} failed: {}",
            DisplayErrorContext(error)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sts::config::RuntimeComponents;
    use aws_sdk_sts::config::endpoint::{DefaultResolver, Params, ResolveEndpoint};
    use aws_sdk_sts::config::http::HttpRequest;
    use aws_smithy_runtime_api::client::http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
    };
    use axum::Router;
    use axum::extract::Form;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const REGION: &str = "eu-west-1";
    const SOURCE_ROLE: &str = "arn:aws:iam::111111111111:role/with-iam/argocd-repo-server-idcat";
    const CENTRAL_ROLE: &str = "arn:aws:iam::132827254700:role/crossplane/idcat-argocd-repo-server";
    const HOUR: Duration = Duration::from_secs(3600);

    /// A request the fake STS saw: the URL the SDK sent it to, its parameters
    /// and its Authorization header.
    #[derive(Debug, Clone)]
    struct Seen {
        url: String,
        params: HashMap<String, String>,
        auth: Option<String>,
    }

    impl Seen {
        fn action(&self) -> &str {
            &self.params["Action"]
        }
    }

    type Recorder = Arc<Mutex<Vec<Seen>>>;

    fn rfc3339(time: SystemTime) -> String {
        humantime::format_rfc3339_seconds(time).to_string()
    }

    fn credentials_xml(access_key_id: &str, lifetime: Duration) -> String {
        format!(
            "<Credentials>\
             <AccessKeyId>{access_key_id}</AccessKeyId>\
             <SecretAccessKey>secret</SecretAccessKey>\
             <SessionToken>session-token</SessionToken>\
             <Expiration>{}</Expiration>\
             </Credentials>",
            rfc3339(SystemTime::now() + lifetime)
        )
    }

    /// The fake STS's answer to `action`.
    fn response(action: &str, central_lifetime: Duration) -> String {
        let result = match action {
            "AssumeRoleWithWebIdentity" => credentials_xml("ASIASOURCE", HOUR),
            "AssumeRole" => credentials_xml("ASIACENTRAL", central_lifetime),
            "GetWebIdentityToken" => format!(
                "<WebIdentityToken>jwt</WebIdentityToken><Expiration>{}</Expiration>",
                rfc3339(SystemTime::now() + Duration::from_secs(3540))
            ),
            _ => panic!("unexpected action {action}"),
        };
        format!(
            "<{action}Response xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
             <{action}Result>{result}</{action}Result>\
             </{action}Response>"
        )
    }

    /// A local STS that records each request and answers AssumeRoleWithWebIdentity,
    /// AssumeRole (with credentials that last `central_lifetime`) and
    /// GetWebIdentityToken (with a token that expires in 59 minutes), except
    /// that the action named in `error` fails with a status and an STS error
    /// code. Returns its address.
    async fn fake_sts(
        central_lifetime: Duration,
        error: Option<(&'static str, StatusCode, &'static str)>,
    ) -> (String, Recorder) {
        let seen: Recorder = Arc::default();
        let recorder = seen.clone();
        let app = Router::new().fallback(post(
            move |headers: HeaderMap, Form(params): Form<HashMap<String, String>>| {
                let recorder = recorder.clone();
                async move {
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .map(|value| value.to_str().unwrap().to_string())
                    };
                    let action = params["Action"].clone();
                    recorder.lock().unwrap().push(Seen {
                        url: header(ORIGINAL_URL).unwrap(),
                        params,
                        auth: header("authorization"),
                    });
                    match error {
                        Some((failing, status, code)) if failing == action => (
                            status,
                            format!(
                                "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
                                 <Error><Type>Sender</Type><Code>{code}</Code>\
                                 <Message>not allowed</Message></Error>\
                                 <RequestId>1</RequestId></ErrorResponse>"
                            ),
                        ),
                        _ => (StatusCode::OK, response(&action, central_lifetime)),
                    }
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address.to_string(), seen)
    }

    const ORIGINAL_URL: &str = "x-original-url";

    /// Sends every request to `address` over plain HTTP, whatever URL the SDK
    /// resolved, and tells the server what that was. The credentials
    /// providers' STS clients can't be given an endpoint URL, only an HTTP
    /// client, so this is how their requests reach the fake STS.
    #[derive(Debug)]
    struct Redirect {
        address: String,
        inner: SharedHttpClient,
    }

    impl HttpClient for Redirect {
        fn http_connector(
            &self,
            settings: &HttpConnectorSettings,
            components: &RuntimeComponents,
        ) -> SharedHttpConnector {
            SharedHttpConnector::new(RedirectConnector {
                address: self.address.clone(),
                inner: self.inner.http_connector(settings, components),
            })
        }
    }

    #[derive(Debug)]
    struct RedirectConnector {
        address: String,
        inner: SharedHttpConnector,
    }

    impl HttpConnector for RedirectConnector {
        fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
            let url = request.uri().to_string();
            let path = url
                .split_once("://")
                .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
                .unwrap_or_else(|| "/".to_string());
            request.headers_mut().insert(ORIGINAL_URL, url);
            request
                .set_uri(format!("http://{}{path}", self.address))
                .unwrap();
            self.inner.call(request)
        }
    }

    /// A projected service account token, removed when dropped.
    struct TokenFile(PathBuf);

    impl TokenFile {
        fn new(contents: &str) -> Self {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "argo-idcat-test-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TokenFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// An issuer whose STS requests all go to `address`.
    async fn issuer(address: &str, token_file: &Path) -> StsIssuer {
        let config = Config {
            idcat_endpoint: "https://idcat.example.com".to_string(),
            github_app: "argocd".to_string(),
            aws_region: REGION.to_string(),
            source_role_arn: SOURCE_ROLE.to_string(),
            web_identity_token_file: token_file.to_path_buf(),
            idcat_role_arn: CENTRAL_ROLE.to_string(),
        };
        let http = SharedHttpClient::new(Redirect {
            address: address.to_string(),
            inner: https_client(),
        });
        StsIssuer::build(&config, http, RetryConfig::disabled()).await
    }

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn actions(seen: &Recorder) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|seen| seen.action().to_string())
            .collect()
    }

    #[tokio::test]
    async fn chain_of_requests_for_an_idcat_token() {
        let (address, seen) = fake_sts(HOUR, None).await;
        let token_file = TokenFile::new("service-account-jwt");
        let before = SystemTime::now();

        let token = issuer(&address, &token_file.0).await.issue().await.unwrap();

        assert_eq!(token.token, "jwt");
        assert!(token.expiration >= before + Duration::from_secs(3539));
        let seen = seen.lock().unwrap().clone();
        let [web_identity, assume_role, get_token] = seen.as_slice() else {
            panic!("expected three requests, got {seen:?}");
        };
        for request in &seen {
            assert_eq!(request.url, format!("https://sts.{REGION}.amazonaws.com/"));
        }

        assert_eq!(
            web_identity.params,
            params(&[
                ("Action", "AssumeRoleWithWebIdentity"),
                ("Version", "2011-06-15"),
                ("RoleArn", SOURCE_ROLE),
                ("RoleSessionName", "argo-idcat"),
                ("WebIdentityToken", "service-account-jwt"),
            ])
        );
        // The token is the credential: the request isn't signed.
        assert_eq!(web_identity.auth, None);

        assert_eq!(
            assume_role.params,
            params(&[
                ("Action", "AssumeRole"),
                ("Version", "2011-06-15"),
                ("RoleArn", CENTRAL_ROLE),
                ("RoleSessionName", "argo-idcat"),
                ("DurationSeconds", "3600"),
            ])
        );
        let auth = assume_role.auth.as_deref().unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=ASIASOURCE/")
                && auth.contains(&format!("/{REGION}/sts/aws4_request")),
            "{auth}"
        );

        // An hour of credentials, less the leeway, less a second or so.
        let mut get_token_params = get_token.params.clone();
        let duration: u64 = get_token_params
            .remove("DurationSeconds")
            .unwrap()
            .parse()
            .unwrap();
        assert!((3535..=3540).contains(&duration), "{duration}");
        assert_eq!(
            get_token_params,
            params(&[
                ("Action", "GetWebIdentityToken"),
                ("Version", "2011-06-15"),
                ("Audience.member.1", "idcat.example.com"),
                ("SigningAlgorithm", "ES384"),
            ])
        );
        let auth = get_token.auth.as_deref().unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=ASIACENTRAL/")
                && auth.contains(&format!("/{REGION}/sts/aws4_request")),
            "{auth}"
        );
    }

    #[tokio::test]
    async fn each_token_gets_new_credentials() {
        let (address, seen) = fake_sts(HOUR, None).await;
        let token_file = TokenFile::new("service-account-jwt");
        let issuer = issuer(&address, &token_file.0).await;

        issuer.issue().await.unwrap();
        issuer.issue().await.unwrap();

        assert_eq!(
            actions(&seen),
            [
                "AssumeRoleWithWebIdentity",
                "AssumeRole",
                "GetWebIdentityToken",
                "AssumeRoleWithWebIdentity",
                "AssumeRole",
                "GetWebIdentityToken"
            ]
        );
    }

    #[tokio::test]
    async fn short_credentials_shorten_the_token_and_the_current_token_file_is_used() {
        let (address, seen) = fake_sts(Duration::from_secs(10 * 60), None).await;
        let token_file = TokenFile::new("first-jwt");
        let issuer = issuer(&address, &token_file.0).await;

        issuer.issue().await.unwrap();
        // As kubelet does when it rotates the token.
        std::fs::write(&token_file.0, "rotated-jwt").unwrap();
        issuer.issue().await.unwrap();

        let seen = seen.lock().unwrap().clone();
        let tokens: Vec<_> = seen
            .iter()
            .filter(|seen| seen.action() == "AssumeRoleWithWebIdentity")
            .map(|seen| seen.params["WebIdentityToken"].as_str())
            .collect();
        assert_eq!(tokens, ["first-jwt", "rotated-jwt"]);
        assert_eq!(seen.len(), 6);
        // Ten minutes of credentials, less the leeway, less a second or so.
        let duration: u64 = seen[5].params["DurationSeconds"].parse().unwrap();
        assert!((535..=540).contains(&duration), "{duration}");
    }

    #[tokio::test]
    async fn sts_error_names_the_failing_step_code_and_message() {
        for (action, code, expected, requests) in [
            (
                "AssumeRoleWithWebIdentity",
                "InvalidIdentityToken",
                "failed to get AWS credentials: \
                 STS AssumeRoleWithWebIdentity failed: InvalidIdentityToken: not allowed",
                1,
            ),
            (
                "AssumeRole",
                "AccessDenied",
                "failed to get AWS credentials: \
                 STS AssumeRole failed: AccessDenied: not allowed",
                2,
            ),
            (
                "GetWebIdentityToken",
                "OutboundWebIdentityFederationDisabled",
                "STS GetWebIdentityToken failed: OutboundWebIdentityFederationDisabled: not allowed",
                3,
            ),
        ] {
            let (address, seen) = fake_sts(HOUR, Some((action, StatusCode::FORBIDDEN, code))).await;
            let token_file = TokenFile::new("service-account-jwt");

            let error = issuer(&address, &token_file.0)
                .await
                .issue()
                .await
                .unwrap_err();

            assert_eq!(error.to_string(), expected);
            assert_eq!(seen.lock().unwrap().len(), requests, "{action}");
        }
    }

    #[tokio::test]
    async fn missing_or_unreadable_token_file() {
        let (address, seen) = fake_sts(HOUR, None).await;
        let missing = TokenFile::new("");
        std::fs::remove_file(&missing.0).unwrap();
        // A directory can't be read as a file, whoever runs the test.
        let unreadable = std::env::temp_dir();

        for (path, reason) in [
            (missing.0.as_path(), "No such file or directory"),
            (unreadable.as_path(), "Is a directory"),
        ] {
            let error = issuer(&address, path).await.issue().await.unwrap_err();

            let prefix = format!(
                "failed to get AWS credentials: failed to read the web identity token file {}: ",
                path.display()
            );
            let message = error.to_string();
            assert!(
                message.starts_with(&prefix) && message.contains(reason),
                "{message}"
            );
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn connection_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let token_file = TokenFile::new("service-account-jwt");

        let error = issuer(&address, &token_file.0)
            .await
            .issue()
            .await
            .unwrap_err();

        assert!(
            error.to_string().starts_with(
                "failed to get AWS credentials: STS AssumeRoleWithWebIdentity failed: dispatch failure"
            ),
            "{error}"
        );
    }

    #[test]
    fn token_duration_fits_in_credentials() {
        for (remaining, expected) in [
            (7200, 3600),
            (3660, 3600),
            (3659, 3599),
            (3600, 3540),
            (600, 540),
            (100, 60),
            (0, 60),
        ] {
            assert_eq!(
                token_duration(Duration::from_secs(remaining)),
                Duration::from_secs(expected),
                "{remaining}"
            );
        }
    }

    #[tokio::test]
    async fn uses_the_regional_endpoint() {
        // us-east-1 is where an SDK that defaults to the global endpoint
        // would differ.
        for region in ["us-east-1", "eu-west-1"] {
            let params = Params::builder().region(region).build().unwrap();

            let endpoint = DefaultResolver::new()
                .resolve_endpoint(&params)
                .await
                .unwrap();

            assert_eq!(
                endpoint.url(),
                format!("https://sts.{region}.amazonaws.com")
            );
        }
    }
}
