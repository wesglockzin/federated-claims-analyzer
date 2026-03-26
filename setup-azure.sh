#!/bin/bash
# setup-azure.sh - Complete Azure setup for Federated Identity & Claims Analyzer
#
# This script automates:
# 1. Azure AD App Registration creation
# 2. Azure Container Registry (ACR) creation
# 3. AKS cluster creation (optional)
# 4. Kubernetes secrets creation
# 5. Application deployment
#
# Prerequisites:
# - Azure CLI installed (az)
# - Docker installed
# - kubectl installed
# - jq installed (for JSON parsing)
# - Logged into Azure: az login

set -e

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================
RESOURCE_GROUP="federated-claims-analyzer-rg"
LOCATION="eastus"
ACR_NAME="federatedclaimsacr"  # Must be globally unique, lowercase, alphanumeric only
AKS_CLUSTER="federated-claims-aks"
APP_NAME="Federated Identity Claims Analyzer"
INGRESS_HOST="federated-claims-analyzer.yourdomain.com"  # UPDATE THIS
NAMESPACE="default"

# Existing secrets from your Cloud Run deployment
# These will be prompted if not set as environment variables
OKTA_DEV_OIDC_SECRET="${OKTA_DEV_OIDC_SECRET:-}"
OKTA_PROD_OIDC_SECRET="${OKTA_PROD_OIDC_SECRET:-}"
OKTA_DEV_API_TOKEN="${OKTA_DEV_API_TOKEN:-}"
OKTA_PROD_API_TOKEN="${OKTA_PROD_API_TOKEN:-}"
ADFS_DEV_CLIENT_SECRET="${ADFS_DEV_CLIENT_SECRET:-}"
ADFS_PROD_CLIENT_SECRET="${ADFS_PROD_CLIENT_SECRET:-}"

# ============================================
# HELPER FUNCTIONS
# ============================================
print_header() {
    echo ""
    echo "==========================================="
    echo "  $1"
    echo "==========================================="
    echo ""
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is required but not installed."
        exit 1
    fi
}

prompt_secret() {
    local var_name=$1
    local description=$2
    local current_value="${!var_name}"

    if [ -z "$current_value" ]; then
        read -sp "Enter $description: " value
        echo ""
        eval "$var_name='$value'"
    fi
}

# ============================================
# PRE-FLIGHT CHECKS
# ============================================
print_header "Pre-flight Checks"

check_command az
check_command docker
check_command kubectl
check_command jq

# Check Azure login
if ! az account show &> /dev/null; then
    echo "❌ Not logged into Azure. Running 'az login'..."
    az login
fi

SUBSCRIPTION=$(az account show --query name -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
echo "✅ Logged into Azure"
echo "   Subscription: $SUBSCRIPTION"
echo "   Tenant ID: $TENANT_ID"

# ============================================
# STEP 1: CREATE RESOURCE GROUP
# ============================================
print_header "Step 1: Resource Group"

if az group show --name $RESOURCE_GROUP &> /dev/null; then
    echo "✅ Resource group '$RESOURCE_GROUP' already exists"
else
    echo "Creating resource group '$RESOURCE_GROUP' in '$LOCATION'..."
    az group create --name $RESOURCE_GROUP --location $LOCATION
    echo "✅ Resource group created"
fi

# ============================================
# STEP 2: CREATE AZURE AD APP REGISTRATION
# ============================================
print_header "Step 2: Azure AD App Registration"

# Check if app already exists
EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [ -n "$EXISTING_APP" ] && [ "$EXISTING_APP" != "null" ]; then
    echo "✅ App Registration '$APP_NAME' already exists"
    AZURE_CLIENT_ID=$EXISTING_APP
else
    echo "Creating Azure AD App Registration..."

    # Create the app registration
    APP_RESULT=$(az ad app create \
        --display-name "$APP_NAME" \
        --sign-in-audience "AzureADMyOrg" \
        --web-redirect-uris "https://$INGRESS_HOST/azure/oidc/callback" \
        --optional-claims '{
            "idToken": [
                {"name": "email", "essential": false},
                {"name": "given_name", "essential": false},
                {"name": "family_name", "essential": false}
            ]
        }')

    AZURE_CLIENT_ID=$(echo $APP_RESULT | jq -r '.appId')
    APP_OBJECT_ID=$(echo $APP_RESULT | jq -r '.id')

    echo "✅ App Registration created"
    echo "   Client ID: $AZURE_CLIENT_ID"
fi

# Get or create client secret
echo "Creating client secret..."
SECRET_RESULT=$(az ad app credential reset \
    --id $AZURE_CLIENT_ID \
    --display-name "k8s-deployment-$(date +%Y%m%d)" \
    --years 2 \
    --query password -o tsv)

AZURE_CLIENT_SECRET=$SECRET_RESULT
echo "✅ Client secret created (save this - it won't be shown again)"

# ============================================
# STEP 3: CREATE AZURE CONTAINER REGISTRY
# ============================================
print_header "Step 3: Azure Container Registry"

if az acr show --name $ACR_NAME --resource-group $RESOURCE_GROUP &> /dev/null; then
    echo "✅ ACR '$ACR_NAME' already exists"
else
    echo "Creating Azure Container Registry..."
    az acr create \
        --resource-group $RESOURCE_GROUP \
        --name $ACR_NAME \
        --sku Basic \
        --admin-enabled true
    echo "✅ ACR created"
fi

ACR_LOGIN_SERVER=$(az acr show --name $ACR_NAME --query loginServer -o tsv)
echo "   Login Server: $ACR_LOGIN_SERVER"

# ============================================
# STEP 4: CREATE AKS CLUSTER
# ============================================
print_header "Step 4: AKS Cluster"

if az aks show --name $AKS_CLUSTER --resource-group $RESOURCE_GROUP &> /dev/null; then
    echo "✅ AKS cluster '$AKS_CLUSTER' already exists"
else
    echo "Creating AKS cluster (this may take several minutes)..."
    az aks create \
        --resource-group $RESOURCE_GROUP \
        --name $AKS_CLUSTER \
        --node-count 2 \
        --node-vm-size Standard_B2s \
        --enable-managed-identity \
        --attach-acr $ACR_NAME \
        --generate-ssh-keys
    echo "✅ AKS cluster created"
fi

# Get AKS credentials
echo "Getting AKS credentials..."
az aks get-credentials --resource-group $RESOURCE_GROUP --name $AKS_CLUSTER --overwrite-existing
echo "✅ kubectl configured for AKS"

# ============================================
# STEP 5: INSTALL NGINX INGRESS CONTROLLER
# ============================================
print_header "Step 5: Nginx Ingress Controller"

if kubectl get namespace ingress-nginx &> /dev/null; then
    echo "✅ Nginx Ingress already installed"
else
    echo "Installing Nginx Ingress Controller..."
    kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.4/deploy/static/provider/cloud/deploy.yaml
    echo "Waiting for Ingress Controller to be ready..."
    kubectl wait --namespace ingress-nginx \
        --for=condition=ready pod \
        --selector=app.kubernetes.io/component=controller \
        --timeout=300s
    echo "✅ Nginx Ingress installed"
fi

# Get Ingress IP
echo "Waiting for External IP..."
sleep 10
INGRESS_IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
echo "   Ingress External IP: $INGRESS_IP"

# ============================================
# STEP 6: COLLECT REMAINING SECRETS
# ============================================
print_header "Step 6: Collect Secrets"

echo "We need a few more secrets for the application."
echo "(Press Enter to skip optional ones)"
echo ""

prompt_secret OKTA_DEV_OIDC_SECRET "Okta DEV OIDC Secret"
prompt_secret ADFS_DEV_CLIENT_SECRET "ADFS DEV Client Secret"
prompt_secret ADFS_PROD_CLIENT_SECRET "ADFS PROD Client Secret"

# Generate Flask secret key
FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "✅ Generated Flask secret key"

# Read SAML certificates if they exist
SAML_CERT=""
SAML_KEY=""
if [ -f "saml_tester.cert" ] && [ -f "saml_tester.key" ]; then
    SAML_CERT=$(cat saml_tester.cert)
    SAML_KEY=$(cat saml_tester.key)
    echo "✅ Found SAML certificates"
else
    echo "⚠️  SAML certificates not found (saml_tester.cert, saml_tester.key)"
    echo "   SAML functionality will be unavailable"
fi

# ============================================
# STEP 7: CREATE KUBERNETES RESOURCES
# ============================================
print_header "Step 7: Create Kubernetes Resources"

# Create ConfigMap
echo "Creating ConfigMap..."
cat <<EOF | kubectl apply -n $NAMESPACE -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: federated-claims-analyzer-config
  labels:
    app: federated-claims-analyzer
data:
  APP_BASE_URL: "https://$INGRESS_HOST"
EOF
echo "✅ ConfigMap created"

# Create Secrets
echo "Creating Secrets..."
kubectl create secret generic federated-claims-analyzer-secrets \
    --from-literal=FLASK_SECRET_KEY="$FLASK_SECRET_KEY" \
    --from-literal=AZURE_OIDC_CLIENT_ID="$AZURE_CLIENT_ID" \
    --from-literal=AZURE_OIDC_CLIENT_SECRET="$AZURE_CLIENT_SECRET" \
    --from-literal=AZURE_OIDC_TENANT_ID="$TENANT_ID" \
    --from-literal=OKTA_DEV_OIDC_SECRET="$OKTA_DEV_OIDC_SECRET" \
    --from-literal=OKTA_PROD_OIDC_SECRET="$OKTA_PROD_OIDC_SECRET" \
    --from-literal=OKTA_DEV_API_TOKEN="$OKTA_DEV_API_TOKEN" \
    --from-literal=OKTA_PROD_API_TOKEN="$OKTA_PROD_API_TOKEN" \
    --from-literal=ADFS_DEV_CLIENT_SECRET="$ADFS_DEV_CLIENT_SECRET" \
    --from-literal=ADFS_PROD_CLIENT_SECRET="$ADFS_PROD_CLIENT_SECRET" \
    --from-literal=SAML_TESTER_CERT="$SAML_CERT" \
    --from-literal=SAML_TESTER_KEY="$SAML_KEY" \
    --dry-run=client -o yaml | kubectl apply -n $NAMESPACE -f -
echo "✅ Secrets created"

# ============================================
# STEP 8: BUILD AND PUSH DOCKER IMAGE
# ============================================
print_header "Step 8: Build and Push Docker Image"

echo "Logging into ACR..."
az acr login --name $ACR_NAME

echo "Building Docker image..."
docker build -t $ACR_LOGIN_SERVER/federated-claims-analyzer:latest .

echo "Pushing to ACR..."
docker push $ACR_LOGIN_SERVER/federated-claims-analyzer:latest
echo "✅ Image pushed to $ACR_LOGIN_SERVER/federated-claims-analyzer:latest"

# ============================================
# STEP 9: DEPLOY APPLICATION
# ============================================
print_header "Step 9: Deploy Application"

# Apply deployment with substituted values
echo "Deploying application..."
sed "s/\${ACR_NAME}/$ACR_NAME/g" kubernetes/deployment.yaml | kubectl apply -n $NAMESPACE -f -

echo "Deploying service..."
kubectl apply -n $NAMESPACE -f kubernetes/service.yaml

echo "Deploying ingress..."
sed "s/\${INGRESS_HOST}/$INGRESS_HOST/g" kubernetes/ingress.yaml | kubectl apply -n $NAMESPACE -f -

echo "✅ Application deployed"

# Wait for pods
echo "Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=federated-claims-analyzer -n $NAMESPACE --timeout=120s

# ============================================
# SUMMARY
# ============================================
print_header "Deployment Complete!"

echo "📋 SUMMARY"
echo "==========================================="
echo ""
echo "Azure Resources:"
echo "  Resource Group:  $RESOURCE_GROUP"
echo "  AKS Cluster:     $AKS_CLUSTER"
echo "  ACR:             $ACR_LOGIN_SERVER"
echo ""
echo "Azure AD App Registration:"
echo "  Client ID:       $AZURE_CLIENT_ID"
echo "  Tenant ID:       $TENANT_ID"
echo ""
echo "Kubernetes:"
echo "  Namespace:       $NAMESPACE"
echo "  Ingress Host:    $INGRESS_HOST"
echo "  Ingress IP:      $INGRESS_IP"
echo ""
echo "==========================================="
echo ""
echo "⚠️  REQUIRED NEXT STEPS:"
echo ""
echo "1. Configure DNS:"
echo "   Point '$INGRESS_HOST' to IP: $INGRESS_IP"
echo ""
echo "2. Configure TLS (choose one):"
echo "   a) Install cert-manager for automatic Let's Encrypt:"
echo "      kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml"
echo ""
echo "   b) Or create a TLS secret manually:"
echo "      kubectl create secret tls federated-claims-analyzer-tls --cert=tls.crt --key=tls.key"
echo ""
echo "3. Test the application:"
echo "   https://$INGRESS_HOST"
echo ""
echo "📝 Useful commands:"
echo "   kubectl get pods -l app=federated-claims-analyzer"
echo "   kubectl logs -l app=federated-claims-analyzer"
echo "   kubectl describe ingress federated-claims-analyzer"
echo ""
