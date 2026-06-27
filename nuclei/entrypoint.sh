#!/bin/sh
set -e
echo "[nuclei] Checking templates (may update if online, uses baked-in otherwise)..."
nuclei -update-templates -silent 2>/dev/null \
    && echo "[nuclei] Templates updated." \
    || echo "[nuclei] Template update skipped (offline) -- using baked-in templates"
echo "[nuclei] Templates ready. Starting API server on :9001"
exec uvicorn server:app --host 0.0.0.0 --port 9001
