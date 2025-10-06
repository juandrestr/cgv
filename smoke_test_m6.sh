#!/usr/bin/env bash
set -euo pipefail

host="http://127.0.0.1:8080"

jqbin="jq"
if ! command -v jq >/dev/null 2>&1; then
  echo "jq required for M6 smoke"; exit 1
fi

echo "== M6 smoke =="
echo "Login (user1@example.com)..."
LOGIN=$(curl -fsS -X POST "$host/auth/login" -H 'content-type: application/json' \
  --data '{"email":"user1@example.com","password":"pass123"}')

ACCESS=$(echo "$LOGIN" | $jqbin -r '.access_token')
REFRESH=$(echo "$LOGIN" | $jqbin -r '.refresh_token')
test "$ACCESS" != "null" -a "$REFRESH" != "null"
echo "Got tokens."

echo "Call /me with access..."
curl -fsS -H "authorization: Bearer $ACCESS" "$host/me" >/dev/null
echo "/me OK"

echo "Refresh (rotate)..."
R1=$(curl -fsS -X POST "$host/auth/refresh" -H 'content-type: application/json' \
  --data "{\"refresh_token\":\"$REFRESH\"}")
NEW_ACCESS=$(echo "$R1" | $jqbin -r '.access_token')
NEW_REFRESH=$(echo "$R1" | $jqbin -r '.refresh_token')
test "$NEW_ACCESS" != "null" -a "$NEW_REFRESH" != "null"
echo "Rotation OK"

echo "Re-use old refresh (should fail)..."
set +e
curl -s -o /dev/null -w "%{http_code}" -X POST "$host/auth/refresh" -H 'content-type: application/json' \
  --data "{\"refresh_token\":\"$REFRESH\"}" | grep -qE '401|400'
RC=$?
set -e
if [ $RC -ne 0 ]; then echo "Old refresh unexpectedly succeeded"; exit 1; fi
echo "Old refresh rejected as expected."

echo "Logout with current refresh..."
curl -fsS -X POST "$host/auth/logout" -H 'content-type: application/json' \
  --data "{\"refresh_token\":\"$NEW_REFRESH\"}" >/dev/null
echo "Logout OK"

echo "Try refresh after logout (should fail)..."
set +e
curl -s -o /dev/null -w "%{http_code}" -X POST "$host/auth/refresh" -H 'content-type: application/json' \
  --data "{\"refresh_token\":\"$NEW_REFRESH\"}" | grep -qE '401|400'
RC=$?
set -e
if [ $RC -ne 0 ]; then echo "Refresh after logout unexpectedly succeeded"; exit 1; fi

echo "== M6 tests PASS =="
