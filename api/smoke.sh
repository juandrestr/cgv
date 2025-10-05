#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://localhost:8080/healthz >/dev/null

# wait up to 30s for ready ok:true
for i in {1..30}; do
  RESP="$(curl -fsS http://localhost:8080/ready || true)"
  echo "$RESP" | grep -Eq '"ok":[[:space:]]*true' && { echo "smoke OK"; exit 0; }
  sleep 1
done

echo "smoke FAILED"
exit 1
