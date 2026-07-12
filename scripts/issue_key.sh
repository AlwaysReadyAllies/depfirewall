#!/usr/bin/env bash
# Issue (or revoke) a depfirewall license key after a Stripe payment lands.
#   ./scripts/issue_key.sh                 # mint + store a new key, prints it (email to customer)
#   ./scripts/issue_key.sh revoke dfw_xxx  # revoke a key
set -euo pipefail
set -a; source /home/croft/.config/ara/secrets.env; set +a
NS=5b2fe85b0c8a46b391f3a629309de10e
API="https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/storage/kv/namespaces/$NS/values"

if [ "${1:-}" = "revoke" ]; then
  curl -sf -X DELETE "$API/$2" -H "Authorization: Bearer $CF_API_TOKEN" >/dev/null
  echo "revoked: $2"
  exit 0
fi

KEY="dfw_$(openssl rand -hex 16)"
curl -sf -X PUT "$API/$KEY" -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: text/plain" \
  -d "{\"plan\":\"pro\",\"repo\":null,\"issued\":\"$(date -u +%F)\"}" >/dev/null
echo "$KEY"
echo "(binds to the customer's repo on first CI run; email it with: add as DEPFIREWALL_KEY secret)"
