#!/usr/bin/env bash
set -euo pipefail
PHONE=${1:-27820000001}

# 1) login + request OTP
curl -sS -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$PHONE\"}" >/dev/null

curl -sS -X POST http://localhost:8080/auth/otp/request \
  -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$PHONE\"}" >/dev/null

# 2) read OTP from logs
OTP=$(docker logs --since=90s cgv-api-1 | sed -n "s/.*\\[OTP\\] phone=${PHONE} code=\\([0-9]\\{6\\}\\).*/\\1/p" | tail -1)
echo "OTP=$OTP"
test -n "$OTP" || { echo "No OTP found"; exit 1; }

# 3) verify OTP -> token
LOGIN=$(curl -sS -X POST http://localhost:8080/auth/otp/verify \
  -H 'Content-Type: application/json' \
  -d "{\"phone\":\"$PHONE\",\"code\":\"$OTP\"}")
TOKEN=$(jq -r '.access_token // empty' <<<"$LOGIN")
test -n "$TOKEN" || { echo "No token in response: $LOGIN"; exit 1; }
echo "TOKEN length: ${#TOKEN}"

# 4) issue R50
ISSUE_KEY="ISSUE-$(date +%s)"
NEW=$(curl -sS -X POST http://localhost:8080/vouchers/issue \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $ISSUE_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"currency":"ZAR","face_value_cents":5000}')
echo "Issue response: $NEW"
CODE=$(jq -r '.code // empty' <<<"$NEW")
test -n "$CODE" || { echo "No code returned"; exit 1; }
echo "CODE=$CODE"

# 5) redeem + replay (same key)
REDEEM_KEY="RIDEM-$(date +%s)"
echo "First redeem:"
curl -sS -X POST http://localhost:8080/vouchers/redeem/self \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $REDEEM_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"code\":\"$CODE\"}" | jq

echo "Replay (same key):"
curl -sS -X POST http://localhost:8080/vouchers/redeem/self \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $REDEEM_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"code\":\"$CODE\"}" | jq
