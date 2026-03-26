#!/bin/bash

# Configuration
# 1. Reuse the working Project ID (avoids billing/API setup headaches)
PROJECT_ID="your-gcp-project-id"

# 2. Change the Service Name (This creates the NEW URL with the correct branding)
APP_NAME="federated-claims-analyzer"
REGION="us-central1"
APP_BASE_URL="https://federated-claims-analyzer.us-central1.run.app"

echo "==========================================="
echo "   Deploying $APP_NAME to Cloud Run...   "
echo "==========================================="

# 1. Run smoke tests before deploying
echo ""
echo "Running pre-deployment smoke tests..."
python3 smoke_test.py
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Smoke tests failed! Aborting deployment."
    exit 1
fi
echo ""
echo "✅ Smoke tests passed! Proceeding with deployment..."
echo ""

# 2. Set the project context
gcloud config set project $PROJECT_ID

# 3. Deploy from Source
#    --source . tells Google to upload the current directory and build it automatically.
#    This fixes the "Dockerfile required" error.
echo "Uploading and deploying to Cloud Run..."
gcloud run deploy $APP_NAME \
  --source . \
  --project $PROJECT_ID \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars APP_BASE_URL=$APP_BASE_URL \
  --update-secrets \
OKTA_DEV_OIDC_SECRET=OKTA_DEV_OIDC_SECRET:latest,\
OKTA_PROD_OIDC_SECRET=OKTA_PROD_OIDC_SECRET:latest,\
OKTA_DEV_API_TOKEN=OKTA_DEV_API_TOKEN:latest,\
OKTA_PROD_API_TOKEN=OKTA_PROD_API_TOKEN:latest,\
ADFS_DEV_CLIENT_SECRET=ADFS_DEV_CLIENT_SECRET:latest,\
ADFS_PROD_CLIENT_SECRET=ADFS_PROD_CLIENT_SECRET:latest,\
FLASK_SECRET_KEY=FLASK_SECRET_KEY:latest,\
GOOGLE_OIDC_CLIENT_ID=GOOGLE_OIDC_CLIENT_ID:latest,\
GOOGLE_OIDC_CLIENT_SECRET=GOOGLE_OIDC_CLIENT_SECRET:latest,\
GOOGLE_ALLOWED_EMAILS=GOOGLE_ALLOWED_EMAILS:latest,\
GOOGLE_ADMIN_EMAILS=GOOGLE_ADMIN_EMAILS:latest,\
FIRESTORE_ALLOWLIST_COLLECTION=FIRESTORE_ALLOWLIST_COLLECTION:latest,\
FIRESTORE_ALLOWLIST_DOC=FIRESTORE_ALLOWLIST_DOC:latest,\
ALLOWLIST_CACHE_TTL_SECONDS=ALLOWLIST_CACHE_TTL_SECONDS:latest,\
SAML_TESTER_CERT=SAML_TESTER_CERT:latest,\
SAML_TESTER_KEY=SAML_TESTER_KEY:latest

echo "==========================================="
echo "   Deployment Complete!"
echo "==========================================="
