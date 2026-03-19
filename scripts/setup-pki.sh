#!/bin/bash

echo "=== Настройка PKI ==="
mkdir -p pki

echo "MyRootPass123" > pki/root-pass.txt
chmod 600 pki/root-pass.txt

./micropki-cli ca init \
  --subject "/CN=Test Root CA/O=MicroPKI Test/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file pki/root-pass.txt \
  --out-dir ./pki/root \
  --validity-days 3650 \
  --force

echo "MyIntermediatePass456" > pki/int-pass.txt
chmod 600 pki/int-pass.txt

./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file pki/root-pass.txt \
  --subject "/CN=Test Intermediate CA/O=MicroPKI Test/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file pki/int-pass.txt \
  --out-dir ./pki/intermediate \
  --validity-days 1825 \
  --pathlen 0 \
  --db-path ./pki/micropki.db

./micropki-cli ca issue-ocsp-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file pki/int-pass.txt \
  --subject "/CN=OCSP Responder/O=MicroPKI Test/C=RU" \
  --san dns:localhost \
  --out-dir ./pki/certs

echo "✓ PKI настроена"