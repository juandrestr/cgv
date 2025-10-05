#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://localhost:8080/healthz >/dev/null
curl -fsS http://localhost:8080/ready | grep -q '"ok": true'
echo "smoke OK"
