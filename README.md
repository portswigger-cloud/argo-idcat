# argo-idcat

Lets argo-cd read private GitHub repositories with installation tokens from
[idcat](https://github.com/PortSwigger/idcat), without changes to argo-cd.

argo-idcat runs as a sidecar of argo-cd's repo-server and answers the one GitHub
API call that argo-cd's GitHub App credentials make,
`POST /app/installations/{id}/access_tokens`, with a token that idcat issued to
the pod's AWS identity (see [Identity](#identity)). argo-cd is told about it through a repository
secret whose GitHub App base URL (meant for GitHub Enterprise) points at the
sidecar, with the repository folded into the path:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: manifests-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: https://github.com/platfrom-cloud/manifests
  githubAppID: "1"
  githubAppInstallationID: "1"
  githubAppEnterpriseBaseUrl: http://127.0.0.1:8181/platfrom-cloud/manifests
  # argo-cd signs a JWT with this before asking for a token. argo-idcat
  # ignores the JWT, so any RSA key will do, e.g. `openssl genrsa 2048`.
  githubAppPrivateKey: |
    <throwaway RSA private key in PEM form>
```

Because argo-cd treats this as ordinary GitHub App credentials, both the
in-process go-git client (used to resolve `HEAD`, branches and tags) and the git
CLI (used to fetch) get the token.

## Identity

The idea with this setup is that idcat can be set up to trust a single JWT
issuer for many argo-cd instances running in different clusters. This is
accomplished by having the sidecar assume a role in the local cluster using the
IAM Roles for ServiceAccounts (IRSA) mechanism, and then having argo-idcat
assume a single central IAM role, which in turn is used to obtain the JWT.

The bearer token argo-idcat presents to idcat is a JWT from AWS STS
[`GetWebIdentityToken`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html)
(IAM outbound identity federation), requested with idcat's host as audience
(`IDCAT_ENDPOINT` without its scheme, e.g. `idcat.example.com`), signing
algorithm `ES384` and a lifetime of just under an hour. Its `iss` is the issuer
of the AWS account that has outbound identity federation enabled, and its `sub`
the ARN of the role that asked for it.

That role is the central role, shared by the repo-servers of every cluster.
argo-idcat reaches it in two steps, both against the region's STS endpoint:

1. It reads a projected service account token with audience
   `sts.amazonaws.com` from `AWS_WEB_IDENTITY_TOKEN_FILE`, and exchanges it
   with `AssumeRoleWithWebIdentity` for credentials of a source role in the
   cluster's own account (`AWS_ROLE_ARN`). This is IRSA, done by argo-idcat
   rather than by EKS's webhook: the source role's trust policy trusts the
   cluster's OIDC provider, for the repo-server's service account (e.g.
   `system:serviceaccount:argo:argocd-repo-server`) and audience
   `sts.amazonaws.com` only.
2. With the source role's credentials, which allow `sts:AssumeRole` on the
   central role, it calls `AssumeRole` for the central role (`IDCAT_ROLE_ARN`),
   and signs `GetWebIdentityToken` with the result.

Both role sessions are named `argo-idcat`, for CloudTrail. argo-idcat uses
these providers only, not the SDK's default chain, so that it can't fall back
to the node's role. It reads the token file each time it fetches credentials,
so it picks up the token kubelet rotates.

The central role's trust policy allows the source roles, for instance by
organisation ID and the roles' name pattern. argo-idcat passes no session
tags, so nothing in that check says which cluster or service account is
asking: each source role's own trust policy is what pins it to the one service
account in its cluster.

So idcat needs a single role, whichever cluster asks, and adding a cluster
needs nothing in idcat or in the account that hosts the central role:

```toml
[[role]]
name = "argocd-repo-server"
audience = "idcat.example.com"  # the host of IDCAT_ENDPOINT
# aws iam get-outbound-web-identity-federation-info, in the account hosting
# the central role
issuer = "https://<id>.tokens.sts.global.api.aws"
# idcat's validator accepts only RS256 and ES256 unless told otherwise.
algorithms = ["ES384"]
claims = { sub = "arn:aws:iam::<account>:role/<path>/<central role>" }
```

AWS documents `sub` as "the ARN of the IAM principal that requested the token",
and its example is a role ARN without a path. Whether the ARN of a role with a
path keeps the path in `sub` is not documented; decode a token to check before
relying on the value above.

The central role may only request tokens with idcat's host as audience and
`DurationSeconds` of at most 3600, which its IAM policy enforces with the
`sts:IdentityTokenAudience` and `sts:DurationSeconds` condition keys, and
outbound identity federation has to be enabled in its account
(`aws iam enable-outbound-web-identity-federation`).

argo-idcat keeps a token until half of its life, as given by the expiration STS
returns, has passed, and requests made meanwhile share it. If STS fails then, it
keeps using the old token while that has more than a minute left; otherwise the
error is returned to argo-cd as a 502. STS won't issue a token that outlives the
credentials signing the request, and the central role's credentials last an
hour, the most STS allows a chained role session. So argo-idcat fetches new
credentials for every token, through both role assumptions, and asks for a
token a minute shorter than they have left: about 59 minutes. That makes three
STS calls per cluster roughly every half hour.

## Configuration

Environment variables, all required; argo-idcat refuses to start without
them:

- `IDCAT_ENDPOINT`: the base URL of idcat, e.g. `https://idcat.example.com`.
- `GITHUB_APP`: the idcat GitHub App to request installation tokens from.
- `AWS_REGION`, or failing that `AWS_DEFAULT_REGION`: `GetWebIdentityToken` is
  not served by the global STS endpoint, so argo-idcat sends all its STS
  requests to the region's.
- `AWS_WEB_IDENTITY_TOKEN_FILE`: the projected service account token, with
  audience `sts.amazonaws.com`.
- `AWS_ROLE_ARN`: the source role, in the cluster's own account.
- `IDCAT_ROLE_ARN`: the central role.

The AWS variables have IRSA's names, but they are set on the sidecar alone
(see [values-argo-idcat.yaml](values-argo-idcat.yaml)), with a projected token
mounted into it alone. The service account is not annotated with a role, so
EKS's IRSA webhook doesn't give argo-cd's own containers AWS credentials.

Everything else is fixed:

- The token endpoint listens on `127.0.0.1:8181`.
- `GET /healthz` is served on `0.0.0.0:8182`, so that kubelet's `httpGet`
  probes, which are sent to the pod IP, can reach it.
- idcat returns a token without its expiry, and may return a cached token with
  as little as ten minutes left. argo-idcat therefore tells argo-cd that each
  token expires after nine minutes, and argo-cd asks again a minute before that.

## Security

The token endpoint does not authenticate its callers, so any container in the
repo-server pod can get a token. Keep it on loopback, and grant the idcat role
only the repositories and permissions it needs.

Every cluster's repo-server has the same identity in idcat. A token for the
central role is good for anything idcat grants that role, so what idcat
grants it is reachable from every cluster with a source role, and from
anything else allowed to assume it. Keep its trust policy to the source role's
name and path within the organisation, the source roles' trust policies to the
one service account, and the central role's permissions to
`sts:GetWebIdentityToken` with the conditions above.

The projected token is mounted only into the argo-idcat container. Anything
else that can get a token for the repo-server's service account with audience
`sts.amazonaws.com`, such as another pod in namespace `argo` that runs as it,
can assume the source role and from there the central role.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
docker buildx build -t argo-idcat:dev .
```

The image is `distroless/base-nossl` (glibc, CA certificates, no OpenSSL) plus
`libgcc_s`, which Rust's std needs for unwinding. TLS is rustls with ring, for
the AWS SDK too: it is built without its default HTTPS client, which uses
aws-lc-rs and so needs cmake, and given one with ring instead; the
credentials providers' own STS clients are given the same one. To check that
neither aws-lc-rs, OpenSSL nor cmake has crept in, all of these should fail to
find the package:

```sh
cargo tree -e all -i aws-lc-rs
cargo tree -e all -i openssl-sys
cargo tree -e all -i cmake
```
