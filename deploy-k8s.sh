#!/bin/bash
# deploy-k8s.sh - Deploy Federated Identity & Claims Analyzer to Kubernetes
#
# Prerequisites:
# 1. Azure CLI logged in: az login
# 2. kubectl configured for your AKS cluster
# 3. Azure Container Registry created
# 4. Secrets configured in kubernetes/secrets.yaml

set -e

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================
RESOURCE_GROUP="your-resource-group"
ACR_NAME="yourcontainerregistry"
AKS_CLUSTER="your-aks-cluster"
NAMESPACE="default"
INGRESS_HOST="federated-claims-analyzer.yourdomain.com"
IMAGE_TAG="latest"

# ============================================
# PRE-FLIGHT CHECKS
# ============================================
echo "==========================================="
echo "   Federated Claims Analyzer - K8s Deploy"
echo "==========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl."
    exit 1
fi

# Check if az CLI is available
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not found. Please install az CLI."
    exit 1
fi

# Check if logged into Azure
if ! az account show &> /dev/null; then
    echo "❌ Not logged into Azure. Run: az login"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# ============================================
# BUILD AND PUSH DOCKER IMAGE
# ============================================
echo "Building and pushing Docker image..."

# Login to ACR
az acr login --name $ACR_NAME

# Build and push image
docker build -t $ACR_NAME.azurecr.io/federated-claims-analyzer:$IMAGE_TAG .
docker push $ACR_NAME.azurecr.io/federated-claims-analyzer:$IMAGE_TAG

echo "✅ Image pushed to $ACR_NAME.azurecr.io/federated-claims-analyzer:$IMAGE_TAG"
echo ""

# ============================================
# DEPLOY TO KUBERNETES
# ============================================
echo "Deploying to Kubernetes..."

# Get AKS credentials if needed
az aks get-credentials --resource-group $RESOURCE_GROUP --name $AKS_CLUSTER --overwrite-existing

# Replace variables in manifests and apply
echo "Applying ConfigMap..."
sed "s/\${INGRESS_HOST}/$INGRESS_HOST/g" kubernetes/configmap.yaml | kubectl apply -n $NAMESPACE -f -

echo "Applying Secrets (if secrets.yaml exists)..."
if [ -f kubernetes/secrets.yaml ]; then
    kubectl apply -n $NAMESPACE -f kubernetes/secrets.yaml
else
    echo "⚠️  kubernetes/secrets.yaml not found. Create it from secrets-template.yaml"
    echo "   Or create secrets manually with: kubectl create secret generic ..."
fi

echo "Applying Deployment..."
sed "s/\${ACR_NAME}/$ACR_NAME/g" kubernetes/deployment.yaml | kubectl apply -n $NAMESPACE -f -

echo "Applying Service..."
kubectl apply -n $NAMESPACE -f kubernetes/service.yaml

echo "Applying Ingress..."
sed "s/\${INGRESS_HOST}/$INGRESS_HOST/g" kubernetes/ingress.yaml | kubectl apply -n $NAMESPACE -f -

echo ""
echo "==========================================="
echo "   Deployment Complete!"
echo "==========================================="
echo ""
echo "Next steps:"
echo "1. Ensure your DNS points $INGRESS_HOST to your Ingress IP"
echo "2. Configure TLS certificate (cert-manager or manual)"
echo "3. Update Azure AD App Registration with callback URL:"
echo "   https://$INGRESS_HOST/azure/oidc/callback"
echo ""
echo "Check deployment status:"
echo "  kubectl get pods -n $NAMESPACE -l app=federated-claims-analyzer"
echo "  kubectl logs -n $NAMESPACE -l app=federated-claims-analyzer"
echo ""
