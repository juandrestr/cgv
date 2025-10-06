#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@tiply.co.za}"
ADMIN_PASS="${ADMIN_PASS:-Admin123!}"
USER_EMAIL="${USER_EMAIL:-smoke.user.m7+$(date +%s)@example.com}"
USER_PASS="User123!"
TMP="$(mktemp -d)"
cleanup(){ rm -rf "$TMP"; }
trap cleanup EXIT

echo "== M7 Smoke =="
echo "API: $API"

# Admin login
curl -sS -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" \
  > "$TMP/admin_login.json" || true

if ! jq -e '.access_token' >/dev/null 2>&1 < "$TMP/admin_login.json"; then
  echo "Admin login failed. Ensure admin user exists and ADMIN_EMAILS includes it."
  echo "Response:"; cat "$TMP/admin_login.json"; exit 1
fi
ADMIN_AT="$(jq -r '.access_token' < "$TMP/admin_login.json")"
echo "Admin login OK"

# 1) Admin creates a normal user via /auth/register
echo "Creating smoke user via admin /auth/register..."
curl -sS -X POST "$API/auth/register" \
  -H "Authorization: Bearer $ADMIN_AT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASS\"}" \
  -o "$TMP/register_user.json" -w "%{http_code}\n" > "$TMP/code.txt" || true

CODE=$(tail -n1 "$TMP/code.txt")
if [[ "$CODE" -ge 200 && "$CODE" -lt 300 ]]; then
  echo "Admin register OK ($CODE)"
else
  echo "Admin /auth/register failed ($CODE)"; cat "$TMP/register_user.json"; exit 1
fi

# 2) Non-admin tries /auth/register -> 403
echo "Logging in as non-admin user..."
curl -sS -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASS\"}" \
  > "$TMP/user_login.json"
USER_AT="$(jq -r '.access_token' < "$TMP/user_login.json")"
[[ -n "$USER_AT" && "$USER_AT" != "null" ]]

echo "Non-admin calling /auth/register (should be 403)..."
curl -sS -X POST "$API/auth/register" \
  -H "Authorization: Bearer $USER_AT" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"nope@example.com\",\"password\":\"Nope123!\"}" \
  -o "$TMP/register_user_forbidden.json" -w "%{http_code}\n" > "$TMP/code2.txt" || true
CODE2=$(tail -n1 "$TMP/code2.txt")
if [[ "$CODE2" == "403" ]]; then
  echo "Non-admin forbidden OK (403)"
else
  echo "Expected 403, got $CODE2"; cat "$TMP/register_user_forbidden.json"; exit 1
fi

# 3) /user/ping with token -> 200
echo "Calling /user/ping with user token..."
curl -sS "$API/user/ping" \
  -H "Authorization: Bearer $USER_AT" \
  -o "$TMP/ping_auth.json" -w "%{http_code}\n" > "$TMP/code3.txt"
CODE3=$(tail -n1 "$TMP/code3.txt")
if [[ "$CODE3" == "200" ]]; then
  echo "/user/ping with token OK (200)"
else
  echo "Expected 200 on /user/ping with token, got $CODE3"; cat "$TMP/ping_auth.json"; exit 1
fi

# 4) /user/ping without token -> 401
echo "Calling /user/ping without token (should be 401)..."
curl -sS "$API/user/ping" \
  -o "$TMP/ping_anon.json" -w "%{http_code}\n" > "$TMP/code4.txt" || true
CODE4=$(tail -n1 "$TMP/code4.txt")
if [[ "$CODE4" == "401" ]]; then
  echo "/user/ping anonymous unauthorized OK (401)"
else
  echo "Expected 401 on /user/ping anonymous, got $CODE4"; cat "$TMP/ping_anon.json"; exit 1
fi

echo "== M7 Smoke PASSED =="
