#!/usr/bin/env bash
set -euo pipefail
API="${API:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@tiply.co.za}"
ADMIN_PASS="${ADMIN_PASS:-Admin123!}"

echo "== M9 smoke =="
TOKEN=$(curl -fsS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" | jq -r .access_token)
echo "token len: ${#TOKEN}"

KEY="SMOKE-$(date -u +%Y%m%d%H%M%S)"
BODY=$(jq -n --arg key "$KEY" \
  '{face_value_cents:500,currency:"ZAR",idempotency_key:$key,retailer_id:"ret-001",
    outlet_id:"out-002",cashier_id:"c-003",till_ref:"TILL-2",provider:"kazang",provider_txn_id:"kz-987"}')

echo "Issuing first time..."
R1=$(curl -fsS -X POST "$API/vouchers/issue" -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' -d "$BODY")
CODE=$(jq -r .code <<<"$R1")
echo "Code: $CODE"

echo "Issuing again with SAME idempotency key (should return SAME code)..."
R2=$(curl -fsS -X POST "$API/vouchers/issue" -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' -d "$BODY")
CODE2=$(jq -r .code <<<"$R2")
test "$CODE" = "$CODE2" && echo "Idempotency OK" || (echo "Idempotency FAIL" && exit 1)

echo "Trigger throttle (2 quick extra calls; expect one 429)"
for k in 1 2; do
  KEY2="SMOKE-$(date -u +%Y%m%d%H%M%S)-$k"
  BODY2=$(jq -n --arg key "$KEY2" \
    '{face_value_cents:500,currency:"ZAR",idempotency_key:$key}')
  curl -s -o /dev/null -w "HTTP:%{http_code}\n" -X POST "$API/vouchers/issue" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$BODY2"
done

echo "Audit check (last 3 voucher events)..."
docker exec -i cgv-db-1 psql -U cgv -d cgv -c \
 "SELECT action, payload->>'idempotency_key' AS idem, subject_type, created_at
  FROM voucher_events WHERE subject_type='voucher'
  ORDER BY created_at DESC LIMIT 3;"
echo "Done."
