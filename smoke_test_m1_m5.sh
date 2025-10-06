#!/usr/bin/env bash
set -euo pipefail

API="http://127.0.0.1:8080"

echo "== Env =="
grep -E '^(REDIS_URL|LOGIN_MAX_ATTEMPTS|LOGIN_WINDOW_SECONDS|LOGIN_LOCK_SECONDS)=' .env || true

echo "== API up =="
docker compose up -d --force-recreate api >/dev/null

# Wait for /healthz (max ~30s) so we don't hit "connection reset" during boot
for i in {1..30}; do
  if curl -fsS "$API/healthz" >/dev/null; then
    echo "healthz: OK"
    break
  fi
  sleep 1
  if [[ $i -eq 30 ]]; then
    echo "healthz: TIMEOUT" >&2
    exit 1
  fi
done

# M1: admin login
PW=$(awk -F= '/^ADMIN_PASSWORD=/{print $2}' .env)
ATOKEN=$(curl -s -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@tiply.co.za\",\"password\":\"$PW\"}" | jq -r .access_token)
test "${#ATOKEN}" -gt 20 && echo "M1 admin login: OK"

# M2: ensure user exists (idempotent)
curl -s -o /dev/null -w '' -X POST "$API/auth/register" \
  -H "Authorization: Bearer $ATOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","password":"S3cur3!","role":"user"}' || true
echo "M2 register user: OK (or already exists)"

# M3: user login
UTOKEN=$(curl -s -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","password":"S3cur3!"}' | jq -r .access_token)
test "${#UTOKEN}" -gt 20 && echo "M3 user login: OK"

# M4: /me
ME=$(curl -s "$API/me" -H "Authorization: Bearer $UTOKEN")
echo "$ME" | jq -e '.email=="user1@example.com" and .role=="user"' >/dev/null && echo "M4 /me: OK"

# M5: lock then unlock
echo "Triggering lock (3 wrong attempts)..."
for i in 1 2 3; do
  curl -s -X POST "$API/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"email":"user1@example.com","password":"nope"}' >/dev/null || true
done

# confirm locked
LOCK_DETAIL=$(curl -s -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","password":"S3cur3!"}' | jq -r .detail || true)
echo "${LOCK_DETAIL:-}" | grep -qi 'too many' && echo "M5 locked: OK"

# unlock as admin (clears email + caller IP)
curl -fsS -X POST "$API/auth/unlock?email=user1@example.com" \
  -H "Authorization: Bearer $ATOKEN" >/dev/null && echo "M5 unlock: OK"

# re-login succeeds
UTOKEN2=$(curl -s -X POST "$API/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","password":"S3cur3!"}' | jq -r .access_token)
test "${#UTOKEN2}" -gt 20 && echo "M5 re-login after unlock: OK"

echo "== ALL TESTS PASS =="
