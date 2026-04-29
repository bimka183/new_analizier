#!/bin/bash
# send_single_anomaly.sh — отправляет одну запись с аномалией
# Запуск: bash send_single_anomaly.sh [ТипАномалии] [IP-источника]
# Пример: bash send_single_anomaly.sh "DoS/DDoS Attack" 10.0.1.50

API="http://localhost:8080"
ANOMALY=${1:-"DoS/DDoS Attack"}
SRC=${2:-"10.0.1.50"}
DST="192.168.1.1"
SP=$((RANDOM % 60000 + 1024))
DP=$((RANDOM % 60000 + 1024))
VOL=$((RANDOM % 50000 + 10000))
LEN=$((RANDOM % 1500 + 64))
TS=$(date +"%Y-%m-%d %H:%M:%S")

curl -s -X POST "$API/api/traffic" \
  -H "Content-Type: application/json" \
  -d "{
    \"flow_id\": \"${SRC}:${SP}-${DST}:${DP}\",
    \"timestamp\": \"${TS}\",
    \"interface\": \"eth0\",
    \"source_ip\": \"${SRC}\",
    \"destination_ip\": \"${DST}\",
    \"source_port\": \"${SP}\",
    \"destination_port\": \"${DP}\",
    \"ip_version\": \"IPv4\",
    \"length\": ${LEN},
    \"traffic_volume\": ${VOL},
    \"flags\": \"SYN,ACK\",
    \"anomalies\": [{\"anomaly_type\": \"${ANOMALY}\"}]
  }" | python3 -m json.tool
