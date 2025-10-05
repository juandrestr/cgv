#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://localhost:8080/healthz >/dev/null

# wait up to 30s for ready ok:true
for i in {1..30}; do
  if curl -fsS http://localhost:8080/ready | grep -q '"ok": true'; then
    echo "smoke OK"
    exit 0
  fi
  sleep 1
done

echo "smoke FAILED"
exit 1
