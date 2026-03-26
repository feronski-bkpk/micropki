#!/bin/bash
cd ~/Рабочий\ стол/micropki

echo "=== Тест блокировки скомпрометированного ключа ==="

# 1. Получаем серийный номер скомпрометированного сертификата
COMPROMISED_SERIAL=$(sqlite3 ./pki/micropki.db "SELECT certificate_serial FROM compromised_keys LIMIT 1;")
echo "Скомпрометированный сертификат: $COMPROMISED_SERIAL"

# 2. Находим файл ключа
KEY_FILE=$(find ./pki/certs -name "*.key.pem" -exec sh -c "openssl rsa -in {} -modulus -noout 2>/dev/null | grep -q '$(sqlite3 ./pki/micropki.db "SELECT public_key_hash FROM compromised_keys LIMIT 1;")' && echo {}" \; 2>/dev/null | head -1)

if [ -z "$KEY_FILE" ]; then
    KEY_FILE=$(ls -t ./pki/certs/*.key.pem 2>/dev/null | head -1)
fi

echo "Используем ключ: $KEY_FILE"

# 3. Создаем новый CSR с тем же ключом и правильным SAN
echo "Создание CSR с скомпрометированным ключом..."
openssl req -new -key "$KEY_FILE" \
    -subj "/CN=blocked-test.local" \
    -addext "subjectAltName=DNS:blocked-test.local" \
    -out /tmp/blocked.csr.pem 2>/dev/null

# 4. Пытаемся выпустить сертификат (должна быть ошибка)
echo -e "\nПопытка выпуска сертификата с скомпрометированным ключом..."
OUTPUT=$(./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass123") \
    --template server \
    --subject "CN=blocked-test.local" \
    --csr /tmp/blocked.csr.pem \
    --out-dir /tmp \
    --db-path ./pki/micropki.db 2>&1)

if echo "$OUTPUT" | grep -q "скомпрометирован"; then
    echo "Тест ПРОЙДЕН: Сертификат с скомпрометированным ключом заблокирован"
elif echo "$OUTPUT" | grep -q "уже существует в БД"; then
    echo "Сертификат уже существует, пропускаем"
else
    echo "Тест НЕ ПРОЙДЕН: Ошибка не связана с компрометацией"
    echo "Вывод: $OUTPUT"
fi