#!/bin/bash

echo "=== Запуск всех сервисов MicroPKI ==="

echo "Запуск репозитория на порту 8080..."
./micropki-cli repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db > repo.log 2>&1 &
REPO_PID=$!
echo "Репозиторий запущен (PID: $REPO_PID)"

sleep 2

echo "Запуск OCSP responder на порту 8081..."
./micropki-cli ocsp serve \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path ./pki/micropki.db \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --cache-ttl 60 > ocsp.log 2>&1 &
OCSP_PID=$!
echo "OCSP responder запущен (PID: $OCSP_PID)"

echo ""
echo "Сервисы запущены. Логи:"
echo "  repo.log - логи репозитория"
echo "  ocsp.log - логи OCSP responder"
echo ""
echo "Проверка статуса:"
echo "  curl http://localhost:8080/health"
echo "  curl -I http://localhost:8081/"
echo ""
echo "Для остановки выполните: kill $REPO_PID $OCSP_PID"