#!/bin/bash

echo "=== Тестирование проверки отзыва ==="

echo "1. Генерация CSR..."
./micropki-cli client gen-csr \
  --subject "/CN=test-revoke.example.com/O=Test Org/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:test-revoke.example.com \
  --out-key test-revoke.key.pem \
  --out-csr test-revoke.csr.pem

echo "2. Получение сертификата..."
./micropki-cli client request-cert \
  --csr test-revoke.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert test-revoke.cert.pem

echo "3. Проверка статуса (ожидается GOOD)..."
./micropki-cli client check-status \
  --cert test-revoke.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem

echo "4. Отзыв сертификата..."
SERIAL=$(openssl x509 -in test-revoke.cert.pem -noout -serial | cut -d= -f2)
./micropki-cli ca revoke $SERIAL --reason keyCompromise --db-path ./pki/micropki.db --force

echo "5. Генерация CRL..."
./micropki-cli ca gen-crl --ca intermediate --next-update 7 --db-path ./pki/micropki.db

echo "6. Повторная проверка (ожидается REVOKED)..."
./micropki-cli client check-status \
  --cert test-revoke.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem

echo "=== Тест завершен ==="