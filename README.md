# Federated Identity & Claims Analyzer

**v7.0.1** — Python/Flask web app for testing and analyzing federated identity protocols. Built for SSO debugging during a large-scale enterprise ADFS → Okta migration.

---

## The Problem

Debugging federated identity failures is slow. When SSO breaks — wrong claims, expired tokens, misconfigured SAML assertions, PKCE failures — you need to see exactly what the IdP returned and why. Browser dev tools get you partway there, but decoding JWTs, validating SAML signatures, checking JWKS, and tracing the full OAuth 2.0 flow requires tooling that doesn't exist out of the box.

This tool closes that gap. It runs full authentication flows against real IdPs and surfaces every token, claim, and assertion in a readable UI — so you can see exactly what the IdP issued, not what you expected it to issue.

---

## What It Does

Full authentication flow testing and token inspection for OIDC and SAML 2.0.

**OIDC (OAuth 2.0):**
- Full authorization code flow with PKCE
- ID token, access token, and refresh token decoding
- JWT claim inspection (important claims separated from standard technical claims)
- Token refresh flow testing
- UserInfo endpoint queries
- Token lifetime validation
- JWKS caching (1-hour TTL)

**SAML 2.0:**
- SP-initiated SSO flows
- SAML assertion decoding and display
- Signature validation
- Attribute mapping inspection

**Multi-IdP support:**
- Okta DEV and PROD (custom and default authorization servers)
- ADFS DEV and PROD
- Azure AD / Entra ID (used as the application login gate)
- Token Lifetime Check (TLC) — query Okta token lifetime settings without triggering a full SSO flow

---

## Architecture

- **Runtime**: Python 3.11 / Flask / Gunicorn (2 workers, 4 threads)
- **Platform**: Azure Container Apps — automatic HTTPS, auto-scaling 0–2 replicas, managed certificates
- **Auth gate**: Azure AD OIDC — all tenant users authorized, no allowlist required
- **Sessions**: Flask signed cookie sessions (multi-worker safe, no filesystem or shared storage dependencies)
- **Secrets**: Azure Container Apps secrets injected as environment variables
- **Timeouts**: 10s HTTP timeout on all IdP requests
- **Security headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, XSS protection
- **Container**: Non-root user, HTTPS-only in production
- **OIDC endpoints**: Re-discovered on each callback for multi-worker safety

---

## Deployment History

| Version | Platform | Notes |
|---------|----------|-------|
| v4.0 | Google Cloud Run | Google OIDC gate + Firestore allowlist |
| v6.0 | Azure Kubernetes Service (AKS) | Azure AD OIDC gate, removed GCP dependencies |
| v7.0 | Azure Container Apps | ~$150/mo → ~$20/mo (87% cost reduction) |

---

## Configuration Required

This tool requires IdP-specific configuration to function. It is not a generic plug-and-play demo — it was built for a specific enterprise environment and will exit at startup if required secrets are missing.

### Required environment variables

```
FLASK_SECRET_KEY
AZURE_OIDC_CLIENT_ID
AZURE_OIDC_CLIENT_SECRET
AZURE_OIDC_TENANT_ID
OKTA_DEV_OIDC_SECRET
OKTA_PROD_OIDC_SECRET         # optional — PROD Okta tests will fail without it
ADFS_DEV_CLIENT_SECRET
ADFS_PROD_CLIENT_SECRET
SAML_TESTER_CERT              # PEM-encoded SP certificate
SAML_TESTER_KEY               # PEM-encoded SP private key
```

### Setup steps

1. Copy `env.config.template` to `env.config` and fill in your IdP credentials:
   - Okta: client ID, client secret, org domain, authorization server ID
   - ADFS: client ID, client secret, ADFS hostname
   - Azure AD: tenant ID, client ID, client secret (for the login gate)

2. Update `saml_settings.py` with your IdP's SAML metadata (SSO URLs, entity IDs, x509 certificates).

3. Register redirect URIs in each IdP application:
   - Azure AD OIDC: `/azure/oidc/callback`
   - Okta OIDC: `/okta/oidc/callback`
   - Okta SAML: `/okta/saml/callback`
   - ADFS OIDC: `/adfs/oidc/callback`
   - ADFS SAML: `/adfs/saml/callback`

4. See `AZURE_AD_SETUP.md` for Azure Container Apps deployment walkthrough.

---

## Deployment

```bash
# Build and deploy to Azure Container Apps
./deploy.sh
```

```bash
# First-time Azure resource provisioning
./setup-azure.sh
```

```bash
# Configure secrets in Azure Container Apps
az containerapp secret set \
  --name federated-claims-analyzer \
  --resource-group federated-claims-rg \
  --secrets \
    flask-secret-key='<secret>' \
    azure-oidc-client-id='<client-id>' \
    azure-oidc-client-secret='<client-secret>' \
    azure-oidc-tenant-id='<tenant-id>' \
    okta-dev-oidc-secret='<secret>' \
    okta-prod-oidc-secret='<secret>' \
    adfs-dev-client-secret='<secret>' \
    adfs-prod-client-secret='<secret>' \
    saml-tester-cert='<cert-pem>' \
    saml-tester-key='<key-pem>'
```

### Local development

```bash
pip install -r requirements.txt
# Add credentials to env.config (see env.config.template)
python app.py
# or
gunicorn --bind 0.0.0.0:8080 --workers 2 --threads 4 app:app
```

### Smoke tests

Run before deploying to catch import errors, missing dependencies, and missing environment variables:

```bash
python smoke_test.py
```

---

## Troubleshooting

**Multi-worker issues**: OIDC endpoint discovery is re-run on each callback. Endpoints discovered in Worker 1 are not available in Worker 2 — this is handled automatically.

**Large session cookies**: SAML responses can push session cookies close to the ~4KB browser limit. This is expected behavior.

**SAML certificate errors**: SAML certs are loaded from Azure Container Apps secrets and written to `/tmp/` at startup. Ensure `SAML_TESTER_CERT` and `SAML_TESTER_KEY` are configured.

---

## Documentation

- [`AZURE_AD_SETUP.md`](AZURE_AD_SETUP.md) — Azure Container Apps deployment and Azure AD app registration walkthrough
- [`SESSION_NOTES.md`](SESSION_NOTES.md) — Detailed change log and session history
- [`AGENTS.md`](AGENTS.md) — Project rules for file management and versioning
- [`Dockerfile`](Dockerfile) — Production container configuration
- [`env.config.template`](env.config.template) — Environment variable reference

---

## Status

Production — actively used for SSO troubleshooting and identity migration validation during a large-scale enterprise ADFS → Okta migration.

---

## Related

- [saml-metadata-parser](../saml-metadata-parser) — Parse and inspect SAML IdP metadata files
- [adfs-okta-migration-tool](../adfs-okta-migration-tool) — Tooling for ADFS → Okta migration workflows

---

Author: Wes Glockzin | License: MIT
