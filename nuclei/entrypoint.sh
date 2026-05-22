#!/bin/sh
set -e
echo "[nuclei] Starting template update in background..."
(nuclei -update-templates -silent 2>/dev/null || echo "[nuclei] Template update skipped (offline or already current)") &
echo "[nuclei] Starting API server on :9001"
exec uvicorn server:app --host 0.0.0.0 --port 9001

