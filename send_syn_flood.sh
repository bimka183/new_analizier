#!/bin/bash
# send_syn_flood.sh — симуляция SYN-flood: отправляет много SYN-пакетов как записи трафика в API
# Запуск:
#   bash send_syn_flood.sh [count] [src_ip] [dst_ip] [dst_port] [sleep_seconds]
# Примеры:
#   bash send_syn_flood.sh
#   bash send_syn_flood.sh 5000 10.0.9.9 192.168.1.1 80 0.001
#
# Важно: это НЕ реальный сетевой SYN-flood. Скрипт генерирует события и шлёт их в backend API
# (как и другие скрипты в репозитории), чтобы проверить детектор/дашборд.

set -euo pipefail

API="${API:-http://localhost:8080}"

COUNT="${1:-2000}"
SRC="${2:-10.0.9.9}"
DST="${3:-192.168.1.1}"
DST_PORT="${4:-80}"
SLEEP_SECS="${5:-0.002}"

ANOMALY="DoS/DDoS Attack"
FLAGS="SYN"
IFACE="${IFACE:-eth0}"
IPV="${IPV:-IPv4}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl не найден. Установите curl и повторите." >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  JSON_PRINTER=(python3 -m json.tool)
else
  JSON_PRINTER=()
fi

echo "=== SYN-flood (симуляция) ==="
echo "API:      $API"
echo "COUNT:    $COUNT"
echo "SRC:      $SRC"
echo "DST:      $DST:$DST_PORT"
echo "SLEEP:    $SLEEP_SECS s"
echo ""

for i in $(seq 1 "$COUNT"); do
  SP=$((RANDOM % 60000 + 1024))
  LEN=$((RANDOM % 300 + 40))               # SYN обычно маленький
  VOL=$((RANDOM % 4000 + 8000))            # завышаем "volume", чтобы детектору было проще
  TS=$(date +"%Y-%m-%d %H:%M:%S")

  curl -s -X POST "$API/api/traffic" \
    -H "Content-Type: application/json" \
    -d "{
      \"flow_id\": \"${SRC}:${SP}-${DST}:${DST_PORT}\",
      \"timestamp\": \"${TS}\",
      \"interface\": \"${IFACE}\",
      \"source_ip\": \"${SRC}\",
      \"destination_ip\": \"${DST}\",
      \"source_port\": \"${SP}\",
      \"destination_port\": \"${DST_PORT}\",
      \"ip_version\": \"${IPV}\",
      \"length\": ${LEN},
      \"traffic_volume\": ${VOL},
      \"flags\": \"${FLAGS}\",
      \"anomalies\": [{\"anomaly_type\": \"${ANOMALY}\"}]
    }" > /dev/null

  if (( i % 250 == 0 )); then
    printf "[%d/%d] %s -> %s:%s (%s)\n" "$i" "$COUNT" "$SRC" "$DST" "$DST_PORT" "$FLAGS"
  fi

  sleep "$SLEEP_SECS"
done

echo ""
echo "=== Готово! Отправлено: $COUNT записей ==="
echo "Подсказка: откройте http://localhost:3000 и посмотрите всплеск SYN-трафика."
