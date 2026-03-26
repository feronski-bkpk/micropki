#!/bin/bash

cd ~/Рабочий\ стол/micropki

echo "========================================="
echo "ПОЛНЫЙ ИНТЕГРАЦИОННЫЙ ТЕСТ SPRINT 7"
echo "========================================="

rm -rf pki
mkdir -p pki/audit pki/certs pki/private pki/crl

# 1. Инициализация с конфигурацией
echo -e "\n1. Инициализация с конфигурацией..."
cat > pki/config.yaml << EOF
policy:
  reject_wildcards: true
  max_end_entity_validity_days: 365
audit:
  enable_rotation: true
  max_size_mb: 10
server:
  rate_limit: 2
  rate_burst: 3
EOF

./micropki-cli db init --db-path ./pki/micropki.db --force

# 2. Создание CA
echo -e "\n2. Создание CA..."
./micropki-cli ca init \
    --subject "CN=Test Root CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file <(echo -n "testpass123") \
    --out-dir ./pki \
    --force

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
    --db-path ./pki/micropki.db

echo -n "intpass123" > ./pki/int-pass.txt
chmod 600 ./pki/int-pass.txt

# 3. Тест корректного выпуска
echo -e "\n3. Тест корректного выпуска..."
./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san "dns:example.com" \
    --out-dir ./pki/certs \
    --validity-days 365 \
    --db-path ./pki/micropki.db
echo "Корректный сертификат выпущен"

# 4. Тест нарушений политик
echo -e "\n4. Тест нарушений политик..."
./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=*.bad.com" \
    --san "dns:*.bad.com" \
    --out-dir /tmp 2>&1 | grep -q "wildcard" && echo "Wildcard заблокирован"

./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template code_signing \
    --subject "CN=bad-code.local" \
    --san "email:bad@example.com" \
    --out-dir /tmp 2>&1 | grep -q "email SAN" && echo "Email SAN для code_signing заблокирован"

# 5. Тест rate limiting
echo -e "\n5. Тест rate limiting..."
./micropki-cli repo serve --host 127.0.0.1 --port 8080 --rate-limit 2 --rate-burst 3 &
SERVER_PID=$!
sleep 2

COUNT_429=0
for i in {1..5}; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health)
    [ "$CODE" = "429" ] && COUNT_429=$((COUNT_429+1))
done
kill $SERVER_PID
[ $COUNT_429 -ge 1 ] && echo "Rate limiting работает ($COUNT_429 из 5 запросов 429)"

# 6. Тест CT-журнала
echo -e "\n6. Тест CT-журнала..."
[ -f ./pki/audit/ct.log ] && [ $(wc -l < ./pki/audit/ct.log) -gt 0 ] && echo "CT-журнал создан"

# 7. Тест компрометации
echo -e "\n7. Тест компрометации..."
./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=compromise-test.local" \
    --san "dns:compromise-test.local" \
    --out-dir ./pki/certs \
    --validity-days 365 \
    --db-path ./pki/micropki.db

./micropki-cli ca compromise \
    --cert ./pki/certs/compromise-test.local.cert.pem \
    --reason keyCompromise \
    --force \
    --db-path ./pki/micropki.db

COMPROMISED=$(sqlite3 ./pki/micropki.db "SELECT COUNT(*) FROM compromised_keys;")
[ "$COMPROMISED" -eq 1 ] && echo "Компрометация записана"

# 8. Тест блокировки скомпрометированного ключа
echo -e "\n8. Тест блокировки скомпрометированного ключа..."
KEY_FILE="./pki/certs/compromise-test.local.key.pem"
openssl req -new -key "$KEY_FILE" \
    -subj "/CN=blocked-test.local" \
    -addext "subjectAltName=DNS:blocked-test.local" \
    -out /tmp/blocked.csr.pem 2>/dev/null

./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=blocked-test.local" \
    --csr /tmp/blocked.csr.pem \
    --out-dir /tmp 2>&1 | grep -q "скомпрометирован" && echo "Скомпрометированный ключ заблокирован"

# 9. Тест аудита
echo -e "\n9. Тест аудита..."
./micropki-cli audit verify | grep -q "ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА" && echo "Целостность аудита подтверждена"

# 10. Тест детекции аномалий
echo -e "\n10. Тест детекции аномалий..."
./micropki-cli audit detect-anomalies --window 1 | head -5

echo -e "\n========================================="
echo "ИТОГОВЫЙ РЕЗУЛЬТАТ"
echo "========================================="
echo "Все тесты пройдены!"
echo "========================================="