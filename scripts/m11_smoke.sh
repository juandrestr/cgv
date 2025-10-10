#!/usr/bin/env bash
set -euo pipefail
API="http://localhost:8080"
MERCHANT_ID="store-001"
SECRET=${MERCHANT_HMAC_SECRET:-newsupersecret}

echo -n "Health: "; curl -fsS "$API/healthz" && echo " OK"

IDEM="POS-$(date +%s)"
BODY='{"face_value_cents":5000,"currency":"ZAR","expires_in_days":180,"metadata":{"store":"main","cashier":"c1"}}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | xxd -p -c 256)

echo "Issue (new idem)..."
RESP=$(curl -sS -X POST "$API/merchant/vouchers/issue" \
  -H "Content-Type: application/json" -H "X-Merchant-Id: $MERCHANT_ID" \
  -H "X-Signature: $SIG" -H "Idempotency-Key: $IDEM" -d "$BODY")
echo "$RESP"
CODE=$(echo "$RESP" | jq -r .code)

echo "Issue (replay idem)..."
RESP2=$(curl -sS -X POST "$API/merchant/vouchers/issue" \
  -H "Content-Type: application/json" -H "X-Merchant-Id: $MERCHANT_ID" \
  -H "X-Signature: $SIG" -H "Idempotency-Key: $IDEM" -d "$BODY")
diff -q <(echo "$RESP" | jq -S .) <(echo "$RESP2" | jq -S .) && echo "Idem OK"

echo "Lookup..."
curl -sS "$API/merchant/vouchers/$CODE" | jq .

echo "Redeem..."
R_IDEM="redeem:POS-$(date +%s)"
R_BODY='{"code":"'"$CODE"'"}'
R_SIG=$(printf %s "$R_BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | xxd -p -c 256)
R1=$(curl -sS -X POST "$API/merchant/vouchers/redeem" \
  -H "Content-Type: application/json" -H "X-Merchant-Id: $MERCHANT_ID" \
  -H "X-Signature: $R_SIG" -H "Idempotency-Key: $R_IDEM" -d "$R_BODY")
echo "$R1"

echo "Redeem (replay idem)..."
R2=$(curl -sS -X POST "$API/merchant/vouchers/redeem" \
  -H "Content-Type: application/json" -H "X-Merchant-Id: $MERCHANT_ID" \
  -H "X-Signature: $R_SIG" -H "Idempotency-Key: $R_IDEM" -d "$R_BODY")
diff -q <(echo "$R1" | jq -S .) <(echo "$R2" | jq -S .) && echo "Redeem idem OK"

echo "Redeem (new idem) -> expect 409..."
R_IDEM2="redeem:POS-REPLAY-$(date +%s)"
curl -i -sS -X POST "$API/merchant/vouchers/redeem" \
  -H "Content-Type: application/json" -H "X-Merchant-Id: $MERCHANT_ID" \
  -H "X-Signature: $R_SIG" -H "Idempotency-Key: $R_IDEM2" -d "$R_BODY" | head -n1
