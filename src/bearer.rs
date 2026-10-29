// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

//! The bearer token presented to idcat, cached until it is half way through
//! its life so that idcat requests don't each wait for a new one.

use crate::idcat::IdcatError;
use std::future::Future;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// When a new token can't be had, the last one is still handed out while it
/// has this long left, enough for idcat to accept it.
const MIN_REMAINING: Duration = Duration::from_secs(60);

/// A JWT and when it stops being valid.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityToken {
    pub token: String,
    pub expiration: SystemTime,
}

/// Mints a new identity token on every call.
pub trait TokenIssuer: Send + Sync + 'static {
    fn issue(&self) -> impl Future<Output = Result<IdentityToken, IdcatError>> + Send;
}

/// The bearer token for a request to idcat.
pub trait BearerSource: Send + Sync + 'static {
    fn bearer(&self) -> impl Future<Output = Result<String, IdcatError>> + Send;
}

/// Hands out the issuer's last token until half its life has passed, then
/// asks for a new one. Callers that arrive while a token is being issued wait
/// for it rather than asking the issuer themselves. If the issuer fails, the
/// last token is used for as long as it is still good.
pub struct CachedBearer<I> {
    issuer: I,
    now: Box<dyn Fn() -> SystemTime + Send + Sync>,
    cached: Mutex<Option<Cached>>,
}

struct Cached {
    token: String,
    refresh_at: SystemTime,
    expiration: SystemTime,
}

impl<I: TokenIssuer> CachedBearer<I> {
    pub fn new(issuer: I) -> Self {
        Self::with_clock(issuer, SystemTime::now)
    }

    fn with_clock(issuer: I, now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        Self {
            issuer,
            now: Box::new(now),
            cached: Mutex::new(None),
        }
    }
}

impl<I: TokenIssuer> BearerSource for CachedBearer<I> {
    async fn bearer(&self) -> Result<String, IdcatError> {
        // Held across issuing, so that concurrent callers share one token.
        let mut cached = self.cached.lock().await;
        let now = (self.now)();
        if let Some(cached) = cached.as_ref()
            && now < cached.refresh_at
        {
            return Ok(cached.token.clone());
        }
        let IdentityToken { token, expiration } = match self.issuer.issue().await {
            Ok(token) => token,
            Err(error) => {
                return match cached.as_ref() {
                    Some(cached) if now + MIN_REMAINING < cached.expiration => {
                        warn!(%error, "failed to refresh identity token, using the previous one");
                        Ok(cached.token.clone())
                    }
                    _ => Err(error),
                };
            }
        };
        // The expiration is STS's, not an assumed lifetime. A token that
        // arrives already expired by our clock is used once and not reused.
        let lifetime = expiration.duration_since(now).unwrap_or_default();
        info!(
            expiration = %humantime::format_rfc3339_seconds(expiration),
            "obtained identity token"
        );
        *cached = Some(Cached {
            token: token.clone(),
            refresh_at: now + lifetime / 2,
            expiration,
        });
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Default)]
    struct FakeIssuer {
        responses: StdMutex<VecDeque<Result<IdentityToken, IdcatError>>>,
        calls: StdMutex<usize>,
        delay: Duration,
    }

    impl FakeIssuer {
        fn returning(responses: Vec<Result<IdentityToken, IdcatError>>) -> Arc<Self> {
            Arc::new(Self {
                responses: StdMutex::new(responses.into()),
                ..Default::default()
            })
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl TokenIssuer for Arc<FakeIssuer> {
        async fn issue(&self) -> Result<IdentityToken, IdcatError> {
            *self.calls.lock().unwrap() += 1;
            tokio::time::sleep(self.delay).await;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("no more tokens")
        }
    }

    fn start() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn token(name: &str, expires_after_secs: u64) -> Result<IdentityToken, IdcatError> {
        Ok(IdentityToken {
            token: name.to_string(),
            expiration: start() + Duration::from_secs(expires_after_secs),
        })
    }

    /// A CachedBearer whose clock reads `clock` seconds after start().
    fn cached(issuer: &Arc<FakeIssuer>) -> (CachedBearer<Arc<FakeIssuer>>, Arc<StdMutex<u64>>) {
        let clock = Arc::new(StdMutex::new(0));
        let reader = clock.clone();
        let bearer = CachedBearer::with_clock(issuer.clone(), move || {
            start() + Duration::from_secs(*reader.lock().unwrap())
        });
        (bearer, clock)
    }

    #[tokio::test]
    async fn reuses_token_until_half_its_life_has_passed() {
        let issuer = FakeIssuer::returning(vec![token("first", 900), token("second", 1800)]);
        let (bearer, clock) = cached(&issuer);

        let mut seen = vec![];
        for at in [0, 300, 449, 450, 899] {
            *clock.lock().unwrap() = at;
            seen.push((at, bearer.bearer().await.unwrap()));
        }

        assert_eq!(
            seen,
            vec![
                (0, "first".to_string()),
                (300, "first".to_string()),
                (449, "first".to_string()),
                (450, "second".to_string()),
                (899, "second".to_string()),
            ]
        );
        assert_eq!(issuer.calls(), 2);
    }

    #[tokio::test]
    async fn short_lived_token_is_refreshed_sooner() {
        let issuer = FakeIssuer::returning(vec![token("short", 60), token("next", 960)]);
        let (bearer, clock) = cached(&issuer);

        bearer.bearer().await.unwrap();
        *clock.lock().unwrap() = 30;

        assert_eq!(bearer.bearer().await.unwrap(), "next");
    }

    #[tokio::test]
    async fn expired_token_is_not_kept() {
        let issuer = FakeIssuer::returning(vec![
            Ok(IdentityToken {
                token: "stale".to_string(),
                expiration: start() - Duration::from_secs(1),
            }),
            token("fresh", 900),
        ]);
        let (bearer, _) = cached(&issuer);

        assert_eq!(bearer.bearer().await.unwrap(), "stale");
        assert_eq!(bearer.bearer().await.unwrap(), "fresh");
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_token() {
        let issuer = Arc::new(FakeIssuer {
            responses: StdMutex::new(vec![token("shared", 900)].into()),
            delay: Duration::from_millis(50),
            ..Default::default()
        });
        let (bearer, _) = cached(&issuer);
        let bearer = Arc::new(bearer);

        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let bearer = bearer.clone();
                tokio::spawn(async move { bearer.bearer().await.unwrap() })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap(), "shared");
        }

        assert_eq!(issuer.calls(), 1);
    }

    #[tokio::test]
    async fn failure_is_returned_and_not_cached() {
        let issuer = FakeIssuer::returning(vec![
            Err(IdcatError("STS is down".to_string())),
            token("recovered", 900),
        ]);
        let (bearer, _) = cached(&issuer);

        let error = bearer.bearer().await.unwrap_err();

        assert_eq!(error.to_string(), "STS is down");
        assert_eq!(bearer.bearer().await.unwrap(), "recovered");
        assert_eq!(issuer.calls(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_falls_back_to_a_token_that_is_still_good() {
        let issuer = FakeIssuer::returning(vec![
            token("first", 900),
            Err(IdcatError("STS is down".to_string())),
            Err(IdcatError("STS is down".to_string())),
            token("second", 1800),
        ]);
        let (bearer, clock) = cached(&issuer);

        bearer.bearer().await.unwrap();
        *clock.lock().unwrap() = 600;
        let fallback = bearer.bearer().await.unwrap();
        *clock.lock().unwrap() = 840;
        let error = bearer.bearer().await.unwrap_err();
        let recovered = bearer.bearer().await.unwrap();

        assert_eq!(fallback, "first");
        assert_eq!(error.to_string(), "STS is down");
        assert_eq!(recovered, "second");
        assert_eq!(issuer.calls(), 4);
    }
}
