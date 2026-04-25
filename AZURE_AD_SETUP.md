# Azure AD App Registration Setup

This guide walks you through creating an Azure AD (Entra ID) App Registration to enable SSO login for the Federated Identity & Claims Analyzer.

## Prerequisites

- Azure tenant with admin or Application Administrator permissions
- Azure Container Apps deployment (or know your application URL)
- Current deployment URL: `https://federated-claims-analyzer.your-env.eastus.azurecontainerapps.io`

## Step 1: Create App Registration

1. Go to [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** (formerly Azure AD)
2. Navigate to **App registrations** → **New registration**
3. Fill in:
   - **Name**: `Federated Identity Claims Analyzer` (or your preferred name)
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**:
     - Platform: `Web`
     - URI: `https://<YOUR-INGRESS-URL>/azure/oidc/callback`
4. Click **Register**

## Step 2: Note the Application Details

After registration, note these values (you'll need them for Kubernetes secrets):

| Field | Location | Secret Name |
|-------|----------|-------------|
| **Application (client) ID** | Overview page | `AZURE_OIDC_CLIENT_ID` |
| **Directory (tenant) ID** | Overview page | `AZURE_OIDC_TENANT_ID` |

## Step 3: Create Client Secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Add a description (e.g., `k8s-deployment`)
3. Choose expiration (recommend 12 or 24 months)
4. Click **Add**
5. **Copy the Value immediately** (you won't see it again) → This is `AZURE_OIDC_CLIENT_SECRET`

## Step 4: Configure Token Claims (Optional)

To include additional user info in tokens:

1. Go to **Token configuration** → **Add optional claim**
2. Select **ID** token type
3. Add claims: `email`, `given_name`, `family_name`, `upn`
4. Click **Add**

## Step 5: API Permissions (Already Configured by Default)

The default `User.Read` permission is sufficient. Verify:

1. Go to **API permissions**
2. Confirm `Microsoft Graph` → `User.Read` (Delegated) is listed
3. If not, click **Add a permission** → **Microsoft Graph** → **Delegated** → `User.Read`

## Step 6: User Assignment (Optional - For Restricting Access Later)

To restrict which users can access the app:

1. Go to **Enterprise applications** (not App registrations)
2. Find your app by name
3. Go to **Properties**
4. Set **Assignment required?** to `Yes`
5. Go to **Users and groups** → **Add user/group**
6. Assign specific users or AD groups

> **Note**: For now, leave "Assignment required" as `No` to allow all tenant users.

## Summary: Values Needed for Azure Container Apps

Configure these secrets in your Container App:

```bash
az containerapp secret set \
  --name federated-claims-analyzer \
  --resource-group my-resource-group \
  --secrets \
    azure-oidc-client-id='<Application (client) ID>' \
    azure-oidc-tenant-id='<Directory (tenant) ID>' \
    azure-oidc-client-secret='<Client secret value>'
```

Or use the Azure Portal:
1. Go to your Container App → **Settings** → **Secrets**
2. Add each secret with the name and value from Step 2 above

## Redirect URI Format

The app expects the callback at:
```
https://<YOUR-APP-URL>/azure/oidc/callback
```

If your Ingress URL changes, update the Redirect URI in Azure:
1. App registrations → Your app → **Authentication**
2. Edit or add the new Redirect URI

<!-- CODEX_WORK_UPDATE_START -->
## Codex Work Participation Update (2026-03-20)
- Performed a repository-wide Markdown refresh to keep documentation aligned.
- Added/updated this note during the current maintenance task.
<!-- CODEX_WORK_UPDATE_END -->
