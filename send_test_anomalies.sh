#!/bin/bash
# send_test_anomalies.sh — отправляет 50 записей с разными аномалиями
# Запуск: bash send_test_anomalies.sh

API="http://localhost:8080"

echo "=== Отправка 50 тестовых записей с аномалиями ==="
echo ""

for i in $(seq 1 50); do
  case $((i % 7)) in
    1) ANOMALY="DoS/DDoS Attack";        SRC="10.0.1.100"; DST="192.168.1.1";  FLAGS="SYN";       VOL=$((RANDOM % 50000 + 10000));;
    2) ANOMALY="Network Overload";        SRC="10.0.2.200"; DST="172.16.0.5";   FLAGS="ACK,PSH";   VOL=$((RANDOM % 80000 + 20000));;
    3) ANOMALY="Worm Activity";           SRC="10.0.3.50";  DST="192.168.2.10"; FLAGS="SYN,ACK";   VOL=$((RANDOM % 30000 + 5000));;
    4) ANOMALY="Confirmed Virus Activity";SRC="10.0.4.150"; DST="172.16.1.20";  FLAGS="PSH,ACK";   VOL=$((RANDOM % 40000 + 8000));;
    5) ANOMALY="Network/Port Scanning";   SRC="10.0.5.75";  DST="192.168.3.30"; FLAGS="SYN";       VOL=$((RANDOM % 20000 + 1000));;
    6) ANOMALY="Point-to-Multipoint";     SRC="10.0.6.200"; DST="172.16.2.40";  FLAGS="ACK";       VOL=$((RANDOM % 60000 + 15000));;
    0) ANOMALY="Flow Switching";          SRC="10.0.7.25";  DST="192.168.4.50"; FLAGS="FIN,ACK";   VOL=$((RANDOM % 25000 + 3000));;
  esac

  SP=$((RANDOM % 60000 + 1024))
  DP=$((RANDOM % 60000 + 1024))
  LEN=$((RANDOM % 1500 + 64))
  MIN=$((i / 6))
  SEC=$((i % 60))
  TS=$(printf "2025-04-06 03:%02d:%02d" $MIN $SEC)

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
      \"flags\": \"${FLAGS}\",
      \"anomalies\": [{\"anomaly_type\": \"${ANOMALY}\"}]
    }" > /dev/null

  printf "[%2d] %-30s %s -> %s\n" "$i" "$ANOMALY" "$SRC:$SP" "$DST:$DP"
  sleep 0.05
done

echo ""
echo "=== Готово! 50 записей отправлено ==="
echo "Откройте http://localhost:3000 и посмотрите данные"
