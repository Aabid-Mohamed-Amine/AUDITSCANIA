#!/bin/bash
# Démarre le daemon ZAP en arrière-plan, attend qu'il soit prêt, puis lance uvicorn.
# Limite la heap JVM pour éviter les OOM sur machine 8GB RAM.
export _JAVA_OPTIONS="-Xmx512m -Xms128m"

ZAP_PORT=${ZAP_PORT:-8090}

zap.sh -daemon -host 127.0.0.1 -port ${ZAP_PORT} -config api.disablekey=true &

echo "Waiting for ZAP daemon on port ${ZAP_PORT}..."
for i in $(seq 1 120); do
  if curl -sf "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/" > /dev/null 2>&1; then
    echo "ZAP daemon ready (${i}x2s)."
    break
  fi
  sleep 2
done

exec python -m uvicorn server:app --host 0.0.0.0 --port 9002
