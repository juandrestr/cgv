#!/usr/bin/env bash
set -euo pipefail
host="http://127.0.0.1:8080"

# Login twice to simulate two sessions
L1=$(curl -fsS -X POST "$host/auth/login" -H 'content-type: application/json' --data '{"email":"user1@example.com","password":"pass123"}')
A1=$(echo "$L1" | jq -r .access_token)
R1=$(echo "$L1" | jq -r .refresh_token)

L2=$(curl -fsS -X POST "$host/auth/login" -H 'content-type: application/json' --data '{"email":"user1@example.com","password":"pass123"}')
R2=$(echo "$L2" | jq -r .refresh_token)

# Call logout_all using an access token
curl -fsS -X POST "$host/auth/logout_all" -H "authorization: Bearer $A1" >/dev/null
echo "logout_all OK"

# Both refresh tokens should now fail
code1=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$host/auth/refresh" -H 'content-type: application/json' --data "{\"refresh_token\":\"$R1\"}")
code2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$host/auth/refresh" -H 'content-type: application/json' --data "{\"refresh_token\":\"$R2\"}")

if [[ "$code1" =~ ^401|400$ ]] && [[ "$code2" =~ ^401|400$ ]]; then
  echo "logout_all invalidated all sessions: OK"
else
  echo "logout_all failed: refresh still valid" >&2
  exit 1
fi
