#!/bin/bash
# Script to create all secrets in Google Secret Manager

cd "$(dirname "$0")"
source env.config

PROJECT_ID="saml-meta-parser"

# Function to create or update secret
create_secret() {
    local name=$1
    local value=$2

    echo "Creating secret: $name"

    # Try to create the secret
    echo -n "$value" | gcloud secrets create "$name" \
        --project="$PROJECT_ID" \
        --data-file=- 2>&1 | grep -v "already exists" || \
    # If it exists, add a new version
    echo -n "$value" | gcloud secrets versions add "$name" \
        --project="$PROJECT_ID" \
        --data-file=- 2>&1
}

# Create all secrets
create_secret "OKTA_DEV_OIDC_SECRET" "$OKTA_DEV_OIDC_SECRET"
create_secret "OKTA_PROD_OIDC_SECRET" "$OKTA_PROD_OIDC_SECRET"
create_secret "OKTA_DEV_API_TOKEN" "$OKTA_DEV_API_TOKEN"
create_secret "OKTA_PROD_API_TOKEN" "$OKTA_PROD_API_TOKEN"
create_secret "ADFS_DEV_CLIENT_SECRET" "$ADFS_DEV_CLIENT_SECRET"
create_secret "ADFS_PROD_CLIENT_SECRET" "$ADFS_PROD_CLIENT_SECRET"
create_secret "FLASK_SECRET_KEY" "$FLASK_SECRET_KEY"
create_secret "GOOGLE_OIDC_CLIENT_ID" "$GOOGLE_OIDC_CLIENT_ID"
create_secret "GOOGLE_OIDC_CLIENT_SECRET" "$GOOGLE_OIDC_CLIENT_SECRET"
create_secret "GOOGLE_ALLOWED_EMAILS" "$GOOGLE_ALLOWED_EMAILS"
create_secret "GOOGLE_ADMIN_EMAILS" "$GOOGLE_ADMIN_EMAILS"
create_secret "FIRESTORE_ALLOWLIST_COLLECTION" "$FIRESTORE_ALLOWLIST_COLLECTION"
create_secret "FIRESTORE_ALLOWLIST_DOC" "$FIRESTORE_ALLOWLIST_DOC"
create_secret "ALLOWLIST_CACHE_TTL_SECONDS" "$ALLOWLIST_CACHE_TTL_SECONDS"
create_secret "BASIC_AUTH_USERNAME" "$BASIC_AUTH_USERNAME"
create_secret "BASIC_AUTH_PASSWORD" "$BASIC_AUTH_PASSWORD"

echo "All secrets created successfully!"
