#!/bin/bash

echo "=== Остановка сервисов MicroPKI ==="

REPO_PID=$(pgrep -f "micropki-cli repo serve" | head -1)
OCSP_PID=$(pgrep -f "micropki-cli ocsp serve" | head -1)

if [ ! -z "$REPO_PID" ]; then
    kill $REPO_PID 2>/dev/null
    echo "Репозиторий остановлен (PID: $REPO_PID)"
else
    echo "Репозиторий не запущен"
fi

if [ ! -z "$OCSP_PID" ]; then
    kill $OCSP_PID 2>/dev/null
    echo "OCSP responder остановлен (PID: $OCSP_PID)"
else
    echo "OCSP responder не запущен"
fi

sleep 1
REMAINING=$(pgrep -f "micropki-cli" | wc -l)
if [ $REMAINING -gt 0 ]; then
    echo "Останавливаю оставшиеся процессы..."
    pkill -f "micropki-cli" 2>/dev/null
fi

echo "Все сервисы остановлены"