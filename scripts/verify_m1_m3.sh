#!/usr/bin/env bash
set -euo pipefail

red() { printf "\033[31m%s\033[0m\n" "$*"; }
grn() { printf "\033[32m%s\033[0m\n" "$*"; }
ylw() { printf "\033[33m%s\033[0m\n" "$*"; }

# --- Preflight: containers up
ylw "Ensuring containers are up..."
docker compose up -d >/dev/null
docker compose ps

# --- M1 Acceptance: health endpoints
ylw "Checking /healthz and /ready..."
H=$(curl -s http://localhost:8080/healthz || true)
R=$(curl -s http://localhost:8080/ready || true)
echo "  /healthz => $H"
echo "  /ready   => $R"
echo "$H" | grep -q '"status":"ok"' && grn "M1 /healthz OK" || red "M1 /healthz FAIL"
echo "$R" | grep -q '"db":true' && echo "$R" | grep -q '"cache":true' && grn "M1 /ready OK" || red "M1 /ready FAIL"

# --- M2 Acceptance: metrics + rate limit baseline + container healthy + version
ylw "Checking /metrics (Prometheus text format)..."
MS=$(curl -s -D - http://localhost:8080/metrics -o /tmp/metrics.txt || true)
echo "$MS" | head -n 1
if echo "$MS" | grep -qi '200'; then
  if grep -qE '^# (HELP|TYPE) ' /tmp/metrics.txt; then
    grn "M2 /metrics OK (Prom format)"
  else
    red "M2 /metrics FAIL (format)"
  fi
else
  red "M2 /metrics FAIL (HTTP)"
fi

ylw "Checking API container health status..."
docker inspect -f '{{.State.Health.Status}}' cgv-api-1 || true

ylw "Checking rate limit headers (best-effort)..."
# 5 rapid requests to see headers (limit policy may vary)
for i in $(seq 1 5); do
  curl -s -D - http://localhost:8080/healthz -o /dev/null | awk 'BEGIN{RS="\r\n\r\n"} NR==1{print}'
done | egrep -i 'x-ratelimit|retry-after' || echo "  (No rate-limit headers seen; policy may be higher or disabled for this path)"

ylw "Checking version/commit injection (env scan in api)..."
docker compose exec -T api /bin/sh -lc 'env | egrep -i "GIT_SHA|GIT_COMMIT|BUILD_VERSION|APP_VERSION" || true'

# --- M3 Acceptance: ORM & Alembic
ylw "Detecting DB creds..."
U=$(docker compose exec -T db sh -lc 'echo $POSTGRES_USER')
D=$(docker compose exec -T db sh -lc 'echo $POSTGRES_DB')
echo "  POSTGRES_USER=$U POSTGRES_DB=$D"

ylw "Alembic head/current..."
docker compose exec -T api alembic history | tail -n +1
docker compose exec -T api alembic current

ylw "Schema check (notes table)..."
docker compose exec -T db psql -U "$U" -d "$D" -c '\d+ notes' >/dev/null && grn "M3 schema OK" || red "M3 schema FAIL"

ylw "CRUD check via API (/notes)..."
NEW=$(curl -s -X POST http://localhost:8080/notes -H 'content-type: application/json' -d '{"msg":"m3-proof"}' || true)
LIST=$(curl -s http://localhost:8080/notes || true)
echo "  POST => $NEW"
echo "  LIST => $(echo "$LIST" | cut -c -200)"

if echo "$NEW" | grep -q '"msg":"m3-proof"'; then
  grn "M3 POST OK"
else
  red "M3 POST FAIL"
fi
if echo "$LIST" | grep -q '"msg":"m3-proof"'; then
  grn "M3 LIST OK"
else
  red "M3 LIST FAIL"
fi

grn "Verification complete."
