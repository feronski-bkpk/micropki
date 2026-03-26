#!/bin/bash
cd ~/Рабочий\ стол/micropki

echo "=== Проверка исправления дублирования system_start ==="

# Очищаем старые данные
rm -rf pki
mkdir -p pki/audit pki/certs pki/private pki/crl

# Первый запуск - должен создать 1 запись system_start
echo "1. Первый запуск (создание БД)..."
./micropki-cli db init --db-path ./pki/micropki.db --force > /dev/null 2>&1

# Второй запуск - не должен создавать новую запись
echo "2. Второй запуск (инициализация корневого CA)..."
./micropki-cli ca init \
    --subject "CN=Test Root CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file <(echo -n "testpass123") \
    --out-dir ./pki \
    --force > /dev/null 2>&1

# Третий запуск
echo "3. Третий запуск (промежуточный CA)..."
./micropki-cli ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file <(echo -n "testpass123") \
    --subject "CN=Test Intermediate CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file <(echo -n "intpass123") \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0 \
    --db-path ./pki/micropki.db > /dev/null 2>&1

# Четвертый запуск
echo "4. Четвертый запуск (выпуск сертификата)..."
echo -n "intpass123" > ./pki/int-pass.txt
chmod 600 ./pki/int-pass.txt

./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=test.local" \
    --san "dns:test.local" \
    --out-dir ./pki/certs \
    --validity-days 365 \
    --db-path ./pki/micropki.db > /dev/null 2>&1

# Пятый запуск
echo "5. Пятый запуск (запрос аудита)..."
./micropki-cli audit query --format table > /dev/null 2>&1

# Подсчет записей system_start
echo ""
echo "=== Результат ==="
SYSTEM_START_COUNT=$(grep -c "system_start" ./pki/audit/audit.log)
TOTAL_ENTRIES=$(wc -l < ./pki/audit/audit.log)

echo "Всего записей в аудите: $TOTAL_ENTRIES"
echo "Записей system_start: $SYSTEM_START_COUNT"

if [ "$SYSTEM_START_COUNT" -le 2 ]; then
    echo "Дублирование исправлено! (system_start: $SYSTEM_START_COUNT)"
else
    echo "Еще есть дублирование (system_start: $SYSTEM_START_COUNT)"
fi

echo ""
echo "=== Последние 3 записи аудита ==="
tail -3 ./pki/audit/audit.log | jq -r '"\(.timestamp) | \(.level) | \(.operation) | \(.status)"' 2>/dev/null || tail -3 ./pki/audit/audit.log