#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}MicroPKI Sprint 2 Test Script${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Функция для проверки результата
check_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1 passed${NC}"
        PASSED_TESTS=$((PASSED_TESTS+1))
        return 0
    else
        echo -e "${RED}✗ $1 failed${NC}"
        return 1
    fi
}

# Функция для проверки наличия ошибки (негативные тесты)
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${GREEN}✓ $1 correctly failed${NC}"
        PASSED_TESTS=$((PASSED_TESTS+1))
        return 0
    else
        echo -e "${RED}✗ $1 should have failed but succeeded${NC}"
        return 1
    fi
}

# Счетчики
TOTAL_TESTS=0
PASSED_TESTS=0

# Очистка предыдущих тестов
echo -e "${YELLOW}Cleaning up previous test files...${NC}"
rm -rf ./test-pki
mkdir -p ./test-pki
mkdir -p ./scripts
echo -e "${GREEN}Cleanup done\n${NC}"

# 1. Создание Root CA
echo -e "${BLUE}Test 1: Root CA Creation${NC}"
echo "TestRootPass123" > ./test-pki/root-pass.txt
./micropki-cli ca init \
    --subject "/CN=Test Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./test-pki/root-pass.txt \
    --out-dir ./test-pki/root \
    --validity-days 3650 > /dev/null 2>&1
check_result "Root CA creation"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 2. Проверка Root CA
echo -e "\n${BLUE}Test 2: Root CA Verification${NC}"
./micropki-cli ca verify --cert ./test-pki/root/certs/ca.cert.pem > /dev/null 2>&1
check_result "Root CA verification"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 3. Создание Intermediate CA
echo -e "\n${BLUE}Test 3: Intermediate CA Creation${NC}"
echo "TestIntermediatePass456" > ./test-pki/intermediate-pass.txt
./micropki-cli ca issue-intermediate \
    --root-cert ./test-pki/root/certs/ca.cert.pem \
    --root-key ./test-pki/root/private/ca.key.pem \
    --root-pass-file ./test-pki/root-pass.txt \
    --subject "/CN=Test Intermediate CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./test-pki/intermediate-pass.txt \
    --out-dir ./test-pki/intermediate \
    --validity-days 1825 \
    --pathlen 0 > /dev/null 2>&1
check_result "Intermediate CA creation"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 4. Проверка Intermediate CA через openssl
echo -e "\n${BLUE}Test 4: OpenSSL Chain Verification${NC}"
openssl verify -CAfile ./test-pki/root/certs/ca.cert.pem \
    ./test-pki/intermediate/certs/intermediate.cert.pem > /dev/null 2>&1
check_result "OpenSSL chain verification"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 5. Выпуск серверного сертификата
echo -e "\n${BLUE}Test 5: Server Certificate Issuance${NC}"
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/intermediate-pass.txt \
    --template server \
    --subject "CN=example.com" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_result "Server certificate issuance"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 6. Проверка серверного сертификата на наличие SAN
echo -e "\n${BLUE}Test 6: Server Certificate SAN Check${NC}"
if openssl x509 -in ./test-pki/certs/example.com.cert.pem -text -noout | grep -q "DNS:example.com"; then
    echo -e "${GREEN}✓ Server certificate SAN check passed${NC}"
    PASSED_TESTS=$((PASSED_TESTS+1))
else
    echo -e "${RED}✗ Server certificate SAN check failed${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 7. Проверка Extended Key Usage для серверного сертификата
echo -e "\n${BLUE}Test 7: Server Certificate EKU Check${NC}"
if openssl x509 -in ./test-pki/certs/example.com.cert.pem -text -noout | grep -q "TLS Web Server Authentication"; then
    echo -e "${GREEN}✓ Server certificate EKU check passed${NC}"
    PASSED_TESTS=$((PASSED_TESTS+1))
else
    echo -e "${RED}✗ Server certificate EKU check failed${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 8. Выпуск клиентского сертификата
echo -e "\n${BLUE}Test 8: Client Certificate Issuance${NC}"
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/intermediate-pass.txt \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --san dns:client.example.com \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_result "Client certificate issuance"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 9. Проверка клиентского EKU
echo -e "\n${BLUE}Test 9: Client Certificate EKU Check${NC}"
# Ищем файл клиентского сертификата
CLIENT_CERT=""
if [ -f "./test-pki/certs/alice_example.com.cert.pem" ]; then
    CLIENT_CERT="./test-pki/certs/alice_example.com.cert.pem"
elif [ -f "./test-pki/certs/Alice_Smith.cert.pem" ]; then
    CLIENT_CERT="./test-pki/certs/Alice_Smith.cert.pem"
else
    CLIENT_CERT=$(find ./test-pki/certs -name "*alice*.pem" -o -name "*Alice*.pem" | head -1)
fi

if [ -n "$CLIENT_CERT" ] && openssl x509 -in "$CLIENT_CERT" -text -noout | grep -q "TLS Web Client Authentication"; then
    echo -e "${GREEN}✓ Client certificate EKU check passed (found: $(basename "$CLIENT_CERT"))${NC}"
    PASSED_TESTS=$((PASSED_TESTS+1))
else
    echo -e "${RED}✗ Client certificate EKU check failed${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 10. Выпуск code signing сертификата
echo -e "\n${BLUE}Test 10: Code Signing Certificate Issuance${NC}"
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/intermediate-pass.txt \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_result "Code signing certificate issuance"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 11. Проверка code signing EKU
echo -e "\n${BLUE}Test 11: Code Signing Certificate EKU Check${NC}"
if openssl x509 -in ./test-pki/certs/MicroPKI_Code_Signer.cert.pem -text -noout | grep -q "Code Signing"; then
    echo -e "${GREEN}✓ Code signing certificate EKU check passed${NC}"
    PASSED_TESTS=$((PASSED_TESTS+1))
else
    echo -e "${RED}✗ Code signing certificate EKU check failed${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 12. Проверка полной цепочки
echo -e "\n${BLUE}Test 12: Full Chain Verification${NC}"
./micropki-cli ca verify-chain \
    --leaf ./test-pki/certs/example.com.cert.pem \
    --intermediate ./test-pki/intermediate/certs/intermediate.cert.pem \
    --root ./test-pki/root/certs/ca.cert.pem > /dev/null 2>&1
check_result "Full chain verification"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 13. Негативный тест: серверный сертификат без SAN
echo -e "\n${BLUE}Test 13: Negative - Server Cert without SAN${NC}"
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/intermediate-pass.txt \
    --template server \
    --subject "CN=bad.example.com" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_error "Server cert without SAN"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 14. Негативный тест: неправильный пароль
echo -e "\n${BLUE}Test 14: Negative - Wrong Password${NC}"
echo "wrong-password" > ./test-pki/wrong-pass.txt
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/wrong-pass.txt \
    --template server \
    --subject "CN=test.example.com" \
    --san dns:test.example.com \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_error "Wrong password"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 15. Негативный тест: code signing с IP SAN
echo -e "\n${BLUE}Test 15: Negative - Code Signing with IP SAN${NC}"
./micropki-cli ca issue-cert \
    --ca-cert ./test-pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./test-pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file ./test-pki/intermediate-pass.txt \
    --template code_signing \
    --subject "CN=Bad Code Signer" \
    --san ip:192.168.1.1 \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./test-pki/certs \
    --validity-days 365 > /dev/null 2>&1
check_error "Code signing with IP SAN"
TOTAL_TESTS=$((TOTAL_TESTS+1))

# 16. Проверка policy.txt
echo -e "\n${BLUE}Test 16: Policy Document Check${NC}"
if [ -f "./test-pki/root/policy.txt" ] && [ -f "./test-pki/intermediate/policy.txt" ]; then
    echo -e "${GREEN}✓ Policy documents exist${NC}"
    PASSED_TESTS=$((PASSED_TESTS+1))
else
    echo -e "${RED}✗ Policy documents missing${NC}"
fi
TOTAL_TESTS=$((TOTAL_TESTS+1))

# Итоги
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}Test Results${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Total tests: ${YELLOW}$TOTAL_TESTS${NC}"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$((TOTAL_TESTS - PASSED_TESTS))${NC}"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "\n${GREEN}✓ ALL TESTS PASSED - Sprint 2 Requirements Met${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed${NC}"
    exit 1
fi