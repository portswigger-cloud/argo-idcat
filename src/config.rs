// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 PortSwigger Ltd

use anyhow::{Context, bail};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// The token endpoint. Callers are not authenticated, so keep it on loopback.
pub const BIND_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8181);
/// Serves only /healthz, for kubelet probes that cannot reach loopback.
pub const HEALTH_BIND_ADDRESS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8182);
/// idcat hands out a cached installation token until 50 minutes into its 60
/// minute life, so a token it returns may have as little as 10 minutes left.
/// Claiming less than that keeps argo-cd from holding on to an expired token;
/// ghinstallation asks again a minute before the expiry we report.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(9 * 60);

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub idcat_endpoint: String,
    pub github_app: String,
    /// The region whose STS endpoint is used: GetWebIdentityToken is not
    /// served by the global one.
    pub aws_region: String,
    /// The source role, in the cluster's own account, assumed with the
    /// projected service account token.
    pub source_role_arn: String,
    /// The projected service account token, audience sts.amazonaws.com.
    pub web_identity_token_file: PathBuf,
    /// The central role, assumed with the source role's credentials, whose
    /// web identity tokens idcat accepts.
    pub idcat_role_arn: String,
}

impl Config {
    /// The audience of the tokens idcat is sent: its endpoint without the
    /// scheme, so a token minted for one idcat is of no use at another.
    pub fn audience(&self) -> &str {
        let endpoint = self.idcat_endpoint.as_str();
        endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .unwrap_or(endpoint)
    }

    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let optional = |name: &str| -> anyhow::Result<Option<String>> {
            match lookup(name) {
                Some(value) if value.trim().is_empty() => bail!("{name} must not be empty"),
                value => Ok(value.map(|value| value.trim().to_string())),
            }
        };
        let required = |name: &str| -> anyhow::Result<String> {
            optional(name)?.with_context(|| format!("{name} is not set"))
        };
        Ok(Self {
            idcat_endpoint: required("IDCAT_ENDPOINT")?
                .trim_end_matches('/')
                .to_string(),
            github_app: required("GITHUB_APP")?,
            aws_region: match optional("AWS_REGION")? {
                Some(region) => region,
                None => optional("AWS_DEFAULT_REGION")?
                    .context("neither AWS_REGION nor AWS_DEFAULT_REGION is set")?,
            },
            source_role_arn: required("AWS_ROLE_ARN")?,
            web_identity_token_file: required("AWS_WEB_IDENTITY_TOKEN_FILE")?.into(),
            idcat_role_arn: required("IDCAT_ROLE_ARN")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    const ALL: [(&str, &str); 7] = [
        ("IDCAT_ENDPOINT", "https://idcat.example.com/"),
        ("GITHUB_APP", "argocd"),
        ("AWS_REGION", "eu-west-1"),
        ("AWS_DEFAULT_REGION", "us-east-1"),
        (
            "AWS_ROLE_ARN",
            "arn:aws:iam::111111111111:role/with-iam/argocd-repo-server-idcat",
        ),
        (
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/secrets/sts.amazonaws.com/serviceaccount/token",
        ),
        (
            "IDCAT_ROLE_ARN",
            "arn:aws:iam::132827254700:role/crossplane/idcat-argocd-repo-server",
        ),
    ];

    /// ALL without the named variables.
    fn without(names: &[&str]) -> Vec<(&'static str, &'static str)> {
        ALL.into_iter()
            .filter(|(k, _)| !names.contains(k))
            .collect()
    }

    #[test]
    fn reads_all_variables() {
        let config = Config::from_lookup(lookup(&ALL)).unwrap();

        assert_eq!(
            config,
            Config {
                idcat_endpoint: "https://idcat.example.com".to_string(),
                github_app: "argocd".to_string(),
                aws_region: "eu-west-1".to_string(),
                source_role_arn: "arn:aws:iam::111111111111:role/with-iam/argocd-repo-server-idcat"
                    .to_string(),
                web_identity_token_file: "/var/run/secrets/sts.amazonaws.com/serviceaccount/token"
                    .into(),
                idcat_role_arn:
                    "arn:aws:iam::132827254700:role/crossplane/idcat-argocd-repo-server".to_string(),
            }
        );
    }

    #[test]
    fn audience_is_the_endpoint_without_its_scheme() {
        for (endpoint, audience) in [
            ("https://idcat.example.com/", "idcat.example.com"),
            ("https://idcat.example.com:8443", "idcat.example.com:8443"),
            ("http://localhost:8080", "localhost:8080"),
        ] {
            let mut vars = without(&["IDCAT_ENDPOINT"]);
            vars.push(("IDCAT_ENDPOINT", endpoint));
            let config = Config::from_lookup(lookup(&vars)).unwrap();

            assert_eq!(config.audience(), audience);
        }
    }

    #[test]
    fn falls_back_to_default_region() {
        let config = Config::from_lookup(lookup(&without(&["AWS_REGION"]))).unwrap();

        assert_eq!(config.aws_region, "us-east-1");
    }

    #[test]
    fn rejects_missing_or_empty() {
        let mut empty_endpoint = without(&["IDCAT_ENDPOINT"]);
        empty_endpoint.push(("IDCAT_ENDPOINT", " "));
        for (vars, expected) in [
            (without(&["IDCAT_ENDPOINT"]), "IDCAT_ENDPOINT is not set"),
            (without(&["GITHUB_APP"]), "GITHUB_APP is not set"),
            (empty_endpoint, "IDCAT_ENDPOINT must not be empty"),
            (
                without(&["AWS_REGION", "AWS_DEFAULT_REGION"]),
                "neither AWS_REGION nor AWS_DEFAULT_REGION is set",
            ),
            (without(&["AWS_ROLE_ARN"]), "AWS_ROLE_ARN is not set"),
            (
                without(&["AWS_WEB_IDENTITY_TOKEN_FILE"]),
                "AWS_WEB_IDENTITY_TOKEN_FILE is not set",
            ),
            (without(&["IDCAT_ROLE_ARN"]), "IDCAT_ROLE_ARN is not set"),
        ] {
            let error = Config::from_lookup(lookup(&vars)).unwrap_err();

            assert_eq!(error.to_string(), expected);
        }
    }
}
