#!/bin/bash
# deploy.sh — Build and deploy Federated Identity & Claims Analyzer to Azure Container Apps
# Usage: ./deploy.sh [version_tag]
#   e.g. ./deploy.sh v7.1.2
# If no version tag provided, prompts for one.

set -e

# VPN TLS inspection — AnyConnect intercepts Azure CLI traffic.
# REQUESTS_CA_BUNDLE adds the Senate CA to Python's trust store.
# AZURE_CLI_DISABLE_CONNECTION_VERIFICATION bypasses AKI extension
# validation failures on Senate intermediate certs.
if [ -f "$HOME/.vpn-ca-bundle.pem" ]; then
  export REQUESTS_CA_BUNDLE="$HOME/.vpn-ca-bundle.pem"
fi
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

APP_NAME="federated-claims-analyzer"
RESOURCE_GROUP="my-resource-group"
ACR="my-acr"

# --- Version Tag ---
VERSION="${1}"
if [ -z "$VERSION" ]; then
  read -rp "Enter version tag (e.g. v7.1.2): " VERSION
fi
if [ -z "$VERSION" ]; then
  echo "ERROR: Version tag is required. Aborting."
  exit 1
fi
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${VERSION}"

echo "==========================================="
echo "  Deploying $APP_NAME $VERSION"
echo "  Image: $IMAGE"
echo "==========================================="

# --- Pre-deployment Smoke Tests ---
# Pure static analysis — no secrets, no venv, no env vars required.
echo ""
echo "Running pre-deployment checks..."
python3 smoke_test.py
if [ $? -ne 0 ]; then
  echo ""
  echo "Pre-deployment checks FAILED. Aborting."
  exit 1
fi
echo ""

# --- Build Image via ACR ---
echo "Building Docker image in Azure Container Registry..."
az acr build \
  --registry "$ACR" \
  --image "${APP_NAME}:${VERSION}" \
  --file Dockerfile \
  .
echo "Image build complete: $IMAGE"
echo ""

# --- Update Container App ---
echo "Updating Container App to new image..."
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --image "$IMAGE"

echo ""
echo "==========================================="
echo "  Deployment complete: $IMAGE"
echo "  URL: https://federated-claims-analyzer.your-env.eastus.azurecontainerapps.io"
echo "==========================================="

# --- Post-deployment Smoke Tests ---
echo ""
echo "Waiting 15s for container to initialize..."
sleep 15
echo "Running post-deployment checks..."
python3 smoke_test.py --post-deploy
if [ $? -ne 0 ]; then
  echo ""
  echo "WARNING: Post-deployment checks FAILED. Container may not be healthy."
  echo "Check Container App logs: az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP"
  exit 1
fi
echo ""
echo "Deployment verified healthy."
