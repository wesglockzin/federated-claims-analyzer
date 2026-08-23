# Federated Identity & Claims Analyzer

## TL;DR

An interactive SSO tester. You pick an identity provider (Okta, ADFS, or Azure / Entra) and a flow (SAML or OIDC), the tool runs the full sign-in against your real account, and shows you exactly what came back — every claim, every attribute, every token, the signed and decoded JWTs, the full SAML assertion.

Built for debugging federation flows: *"what does the SAML response actually contain?"*, *"what claims is Okta really sending?"*, *"why is the email field showing as UPN?"*.

## What this tool is — and what it isn't

**It is:**
- A live, interactive SSO probe against your real IdPs (Okta DEV/STG/PROD, ADFS, Azure / Entra)
- A claims/attribute inspector — decodes JWTs, parses SAML assertions, surfaces every field
- A safe place to run repeatable flows with the option to force fresh-login (no cached session interference)
- Operator-facing — for IAM team and federation troubleshooting

**It isn't:**
- **Not a user-management tool** — it doesn't create / modify users
- **Not a config tool** — it tests SSO; it doesn't change IdP config
- **Not a load tester** — single-flow interactive
- **Not a substitute for Okta/ADFS event logs** for production debugging — use those for what users actually experienced; use this for what *you* see when you reproduce

## Quick start — 30 seconds

1. Sign in (work email; on VPN)
2. Pick the IdP you want to test (Okta / ADFS / Azure)
3. Pick the protocol (SAML or OIDC)
4. Click "Run test"
5. You'll be redirected to the IdP, authenticate, and bounce back to the tool with the full response decoded

## How to use it

### Test modes

| IdP | Protocols supported |
|---|---|
| **Okta** (DEV / STG / PROD) | SAML 2.0, OIDC |
| **ADFS** | SAML 2.0, OIDC |
| **Azure / Entra** | OIDC |

### Fresh-login mode

There's a toggle that forces the IdP to ignore any cached session — OIDC sends `prompt=login` and `max_age=0`; SAML sends `ForceAuthn=true`. Use this when:
- You're testing a flow change and don't want a stale session to mask it
- You want to verify what happens for a "fresh" user
- You suspect cached-session interference in a bug report

Without fresh-login, the IdP may silently reuse a session and skip the auth ceremony — convenient for repeat testing, but misleading if you're chasing a particular auth issue.

### What you see after the test

| Section | What's in it |
|---|---|
| **Test result banner** | Success / failure with the high-level reason |
| **All claims / attributes** | Every key-value pair released by the IdP |
| **Raw tokens** | Decoded JWT(s) for OIDC, decoded XML for SAML — both header, body, and signature parsed |
| **Validation status** | Whether signature verification passed, whether expected claims are present, etc. |
| **Network detail** | Discovery URL, token endpoint, userinfo endpoint, redirect URIs used |

## Common workflows

### "Is the email claim being released?"
- Pick the IdP and protocol the SP uses
- Run a test under your own account
- Look at the claims/attributes panel — `email` should appear with your address

### "Is force-authn actually working?"
- Enable fresh-login
- Run the test
- The IdP should prompt for credentials even if you have a session

### "What does an Okta SAML response actually look like?"
- Pick Okta + SAML 2.0
- Run the test
- The SAML response is decoded and pretty-printed in the result page

### "Compare Okta and ADFS NameID values"
- Run an Okta SAML test, note the NameID
- Run an ADFS SAML test, note the NameID
- The differences (format, value, transform behavior) are visible side-by-side

---

## Deep dive — how it actually works

### Architecture

```
Browser ───▶ Flask app (ACA)
                │
                │  redirects user to IdP for auth (SP-initiated)
                ▼
              [Okta / ADFS / Azure / Entra]
                │
                │  user authenticates; IdP redirects back with response
                ▼
         /<idp>/<protocol>/callback in Flask app
                │
                │  decode, validate signature, extract claims
                ▼
              Render result page with full payload
```

### SAML flow

1. Tool builds a SAML `AuthnRequest` with the SP's certificate (`saml_tester.cert`/`saml_tester.key`)
2. POSTs the request to the IdP's SSO URL via browser redirect
3. IdP authenticates the user (may invoke Duo, MFA, etc.)
4. IdP POSTs the SAML `Response` back to the ACS URL on this tool (`/saml/acs`)
5. Tool verifies the signature against the IdP's metadata cert
6. Decodes the assertion, extracts all attribute statements
7. Renders the decoded payload

### OIDC flow

1. Tool builds an `authorize` URL with `response_type=code`, optional `prompt=login`, etc.
2. Redirects browser to the IdP's authorization endpoint
3. User authenticates
4. IdP redirects back with a `code` to the registered redirect URI (`/<idp>/oidc/callback`)
5. Tool exchanges the code for tokens via the IdP's token endpoint
6. Decodes the ID token (JWT), validates signature against the IdP's JWKS
7. Calls userinfo endpoint to retrieve additional claims
8. Renders the decoded ID token + access token + userinfo response

### JWKS caching

JWKS keys (used to verify OIDC ID token signatures) are cached for `JWKS_CACHE_TTL=3600` seconds (1 hour) to avoid hammering the IdP's well-known endpoint on every test. The cache is per-JWKS-URI.

### Identity
Calls IdPs as **`FederatedClaimsAnalyzer/<version> (internal-tools)`** via the shared `wes_tools_http.make_session()` helper. Same session is reused across all calls in the flow.

### SP cert
The tool's own SAML signing keypair lives in `saml_tester.cert` / `saml_tester.key`. The IdPs trust this cert because we've configured each Okta/ADFS test app to expect signed requests from it.

## Common questions

### "Why did the test redirect to host.example.gov?"
That's the tool's own OIDC sign-in flow — you're being asked to sign in to *this tool*, not the IdP you're testing. After you sign in, the actual test flow begins.

### "Why doesn't this work on my mobile device?"
The SAML keypair is local to the tool, and some IdP test apps have an ACS URL pinned to the deployed instance. Mobile flows that try to use the local SP cert from a tunnel won't authenticate cleanly. Stick to desktop.

### "The test says signature verification failed"
Most common cause: the IdP's signing cert rotated, and the metadata fetch returned stale keys. Wait for the JWKS cache TTL to expire (or restart the container) and retry.

### "Can I test against a custom IdP?"
Not currently — the tool is pinned to the three configured IdPs (Okta, ADFS, Azure). Adding a new IdP requires registering a test app on that IdP and adding the config block to `sso_tester_logic.py`.

### "Will running the test affect production?"
The test signs in as YOU, generates real auth events in the IdP's log, and creates a real session. That session is local to this tool's browser tab; it doesn't grant access to anything else. The events show up in Okta system log and the Change Auditor (where you can see your own activity).

---

## Architecture (for the nerds)

- **Stack:** Flask + gunicorn, deployed to Azure Container Apps in `your-resource-group`
- **Auth (to use this tool):** OIDC via the shared "Admin SSO App" app
- **SP signing keypair:** `saml_tester.cert` / `saml_tester.key`, mounted into the image at build time
- **OIDC stack:** `authlib` for IdP-side OAuth, `python-jose` for JWT validation, `python-jwt`-style JWKS fetching
- **SAML stack:** `python3-saml` (OneLogin's library) for AuthnRequest construction, signature validation, assertion parsing
- **HTTP identity:** `FederatedClaimsAnalyzer/<APP_VERSION> (internal-tools)` UA via `wes_tools_http.make_session()` — module-level `_session` reused across all calls in a flow
- **JWKS caching:** in-memory dict keyed by JWKS URI, 1-hour TTL
- **In-tool docs:** this page renders from `HOWTO.md` next to `app.py`, via `wes_tools_docs.register_howto()`
- **Source:** `<internal-source-path>`

## What's not here yet

- WS-Federation testing (ADFS is configured for SAML/OIDC only in this tool)
- Custom IdP support (would require config-driven IdP registration)
- Side-by-side comparison view (multiple test results shown together)
- History — past test results aren't persisted; close the tab and they're gone

Speak up if any of these would help.
