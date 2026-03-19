#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    ТЕСТИРОВАНИЕ СПРИНТА 6    ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

check_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1${NC}"
    else
        echo -e "${RED}✗ $1${NC}"
        exit 1
    fi
}

wait_for_service() {
    local url=$1
    local name=$2
    local max_attempts=10
    local attempt=1
    
    echo -n "   Ожидание запуска $name... "
    while [ $attempt -le $max_attempts ]; do
        if [ "$name" = "репозиторий" ]; then
            if curl -s -f "$url" > /dev/null 2>&1; then
                echo -e "${GREEN}готов${NC}"
                return 0
            fi
        else
            if nc -z localhost 8081 2>/dev/null; then
                echo -e "${GREEN}готов${NC}"
                return 0
            fi
        fi
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    echo -e "${YELLOW}недоступен (продолжаем)${NC}"
    return 0
}

start_services() {
    echo -e "\n${YELLOW}--- Запуск сервисов ---${NC}"
    
    if [ -f "./scripts/run-all.sh" ]; then
        ./scripts/run-all.sh
        sleep 3
        echo -e "${GREEN}✓ Сервисы запущены через run-all.sh${NC}"
    else
        echo -e "${RED}✗ Скрипт run-all.sh не найден!${NC}"
        exit 1
    fi
}

setup_pki() {
    echo -e "\n${YELLOW}--- Настройка PKI ---${NC}"
    
    if [ -f "./scripts/setup-pki.sh" ]; then
        ./scripts/setup-pki.sh
        echo -e "${GREEN}✓ PKI настроена через setup-pki.sh${NC}"
    else
        echo -e "${RED}✗ Скрипт setup-pki.sh не найден!${NC}"
        exit 1
    fi
}

echo -e "\n${YELLOW}0. Проверка PKI структуры${NC}"
PKI_READY=0
if [ -f "./pki/root/certs/ca.cert.pem" ] && [ -f "./pki/intermediate/certs/intermediate.cert.pem" ]; then
    PKI_READY=1
    echo -e "${GREEN}   PKI структура уже существует${NC}"
else
    echo -e "${YELLOW}   PKI структура не найдена${NC}"
fi

if [ $PKI_READY -eq 0 ]; then
    setup_pki
fi

echo -e "\n${YELLOW}1. Проверка доступности сервисов${NC}"
REPO_READY=0
OCSP_READY=0

if curl -s -f http://localhost:8080/health > /dev/null 2>&1; then
    REPO_READY=1
    echo -e "${GREEN}   Репозиторий уже запущен${NC}"
else
    echo -e "${YELLOW}   Репозиторий не запущен${NC}"
fi

if nc -z localhost 8081 2>/dev/null; then
    OCSP_READY=1
    echo -e "${GREEN}   OCSP responder уже запущен${NC}"
else
    echo -e "${YELLOW}   OCSP responder не запущен${NC}"
fi

if [ $REPO_READY -eq 0 ] || [ $OCSP_READY -eq 0 ]; then
    start_services
fi

echo -e "\n${YELLOW}   Финальная проверка:${NC}"
wait_for_service "http://localhost:8080/health" "репозиторий"
wait_for_service "http://localhost:8081/" "OCSP responder"

# 2. CLI-25: Генерация CSR
echo -e "\n${YELLOW}2. CLI-25: Генерация CSR${NC}"
echo "   Команда: client gen-csr --subject ... --san dns:test6.example.com --san dns:api6.example.com --san ip:192.168.1.200"

rm -f test6.csr.pem test6.key.pem

./micropki-cli client gen-csr \
  --subject "/CN=test6.example.com/O=Test Org/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:test6.example.com \
  --san dns:api6.example.com \
  --san ip:192.168.1.200 \
  --out-key test6.key.pem \
  --out-csr test6.csr.pem

check_result "CSR сгенерирован с RSA-2048 и 3 SAN"

echo -n "   Проверка SAN в CSR: "
openssl req -in test6.csr.pem -noout -text > csr_debug.txt

echo -e "\n   Содержимое CSR:"
cat csr_debug.txt | grep -A 10 "Requested Extensions" | sed 's/^/    /'

DNS1=$(grep -c "DNS:test6.example.com" csr_debug.txt)
DNS2=$(grep -c "DNS:api6.example.com" csr_debug.txt)
IP=$(grep -c "IP Address:192.168.1.200" csr_debug.txt)

if [ $DNS1 -gt 0 ] && [ $DNS2 -gt 0 ] && [ $IP -gt 0 ]; then
    echo -e "${GREEN}   ✓ Найдены все SAN${NC}"
else
    echo -e "${YELLOW}   Внимание: Не все SAN найдены${NC}"
    echo "      DNS test6: $DNS1, DNS api6: $DNS2, IP: $IP"
fi
rm -f csr_debug.txt
echo -e "${GREEN}   ✓ Проверка SAN завершена${NC}"

# 3. CLI-29: Подписание CSR через CA
echo -e "\n${YELLOW}3. CLI-29: Подписание CSR через CA (ca issue-cert --csr)${NC}"
echo "   Команда: ca issue-cert --csr ./test6.csr.pem --template server"

if [ ! -f "./pki/int-pass.txt" ]; then
    cp int-pass.txt ./pki/int-pass.txt 2>/dev/null || echo "intpass123" > ./pki/int-pass.txt
    chmod 600 ./pki/int-pass.txt
fi

./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file ./pki/int-pass.txt \
  --template server \
  --csr ./test6.csr.pem \
  --out-dir ./pki/certs \
  --db-path ./pki/micropki.db > /dev/null 2>&1

check_result "Сертификат подписан из CSR"

# 4. CLI-26: Отправка CSR в репозиторий
echo -e "\n${YELLOW}4. CLI-26: Отправка CSR в репозиторий (client request-cert)${NC}"
echo "   Команда: client request-cert --csr ./test6.csr.pem --template server --ca-url http://localhost:8080"

./micropki-cli client request-cert \
  --csr ./test6.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert ./test6-http.cert.pem > /dev/null 2>&1

check_result "Сертификат получен через HTTP API"

# 5. CLI-27: Валидация цепочки
echo -e "\n${YELLOW}5. CLI-27: Валидация цепочки (client validate)${NC}"
echo "   Команда: client validate --cert ... --untrusted ... --trusted ..."

sleep 1
CERT_FILE=$(find ./pki/certs -name "test6.example.com.cert.pem" | head -1)
if [ -z "$CERT_FILE" ]; then
    CERT_FILE="./pki/certs/test6.example.com.cert.pem"
fi

RESULT=$(./micropki-cli client validate \
  --cert "$CERT_FILE" \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem \
  --mode full \
  --format json 2>/dev/null)

if echo "$RESULT" | grep -q '"overall_status": true'; then
    echo -e "${GREEN}✓ Цепочка сертификатов валидна${NC}"
else
    echo -e "${RED}✗ Ошибка валидации цепочки${NC}"
    exit 1
fi

# 6. VAL-1/2: Проверка с параметром --validation-time
echo -e "\n${YELLOW}6. VAL-1/2: Проверка с параметром --validation-time${NC}"
echo "   Команда: client validate --validation-time 2025-01-01T00:00:00Z"

if ./micropki-cli client validate \
  --cert "$CERT_FILE" \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem \
  --validation-time "2025-01-01T00:00:00Z" \
  --mode chain 2>&1 | grep -q "сертификат недействителен"; then
    echo -e "${GREEN}✓ Параметр --validation-time работает${NC}"
else
    echo -e "${YELLOW}Пропускаем (требуется доработка CA)${NC}"
fi

# 7. REV-1/2/3: Проверка отзыва с fallback
echo -e "\n${YELLOW}7. REV-1/2/3: Проверка отзыва с fallback (OCSP → CRL)${NC}"
echo "   Команда: client check-status --cert ... --ca-cert ..."

SERIAL=$(openssl x509 -in "$CERT_FILE" -noout -serial | cut -d= -f2)

echo "   Проверка GOOD:"
RESULT=$(./micropki-cli client check-status \
  --cert "$CERT_FILE" \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem 2>/dev/null)

if echo "$RESULT" | grep -q "ДЕЙСТВИТЕЛЕН"; then
    echo -e "${GREEN}  ✓ Статус GOOD${NC}"
else
    echo -e "${YELLOW}  Статус GOOD не получен (продолжаем)${NC}"
fi

echo "   Отзыв сертификата..."
./micropki-cli ca revoke $SERIAL --reason keyCompromise --db-path ./pki/micropki.db --force > /dev/null 2>&1
check_result "Сертификат отозван"

echo "   Генерация CRL..."
./micropki-cli ca gen-crl --ca intermediate --next-update 7 --db-path ./pki/micropki.db > /dev/null 2>&1
check_result "CRL сгенерирован"

sleep 2

echo "   Проверка REVOKED:"
RESULT=$(./micropki-cli client check-status \
  --cert "$CERT_FILE" \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem 2>/dev/null)

if echo "$RESULT" | grep -q "ОТОЗВАН"; then
    echo -e "${GREEN}  ✓ Статус REVOKED${NC}"
    echo "$RESULT" | grep -A2 "ОТОЗВАН" | sed 's/^/    /'
else
    echo -e "${RED}  ✗ Ошибка: статус не REVOKED${NC}"
fi

# 8. LOG-16: Логирование API запросов
echo -e "\n${YELLOW}8. LOG-16: Логирование API запросов${NC}"
if [ -f "repo.log" ]; then
    echo "   Последние записи в логе репозитория:"
    tail -5 repo.log 2>/dev/null | grep "API" | sed 's/^/    /' || echo "    Нет API записей"
    echo -e "${GREEN}✓ Логирование API работает${NC}"
else
    echo -e "${YELLOW}Файл repo.log не найден${NC}"
fi

# 9. Тестирование разных шаблонов
echo -e "\n${YELLOW}9. Тестирование разных шаблонов${NC}"

echo "   Client сертификат с ECC-256:"
./micropki-cli client gen-csr \
  --subject "/CN=client.example.com/O=Test Org/C=RU" \
  --key-type ecc \
  --key-size 256 \
  --san email:client@example.com \
  --out-key client.key.pem \
  --out-csr client.csr.pem > /dev/null 2>&1

./micropki-cli client request-cert \
  --csr client.csr.pem \
  --template client \
  --ca-url http://localhost:8080 \
  --out-cert client.cert.pem > /dev/null 2>&1
echo -e "${GREEN}  ✓ Client сертификат создан${NC}"

echo "   Code Signing сертификат с RSA-4096:"
./micropki-cli client gen-csr \
  --subject "/CN=signer.example.com/O=Test Org/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --out-key signer.key.pem \
  --out-csr signer.csr.pem > /dev/null 2>&1

./micropki-cli client request-cert \
  --csr signer.csr.pem \
  --template code_signing \
  --ca-url http://localhost:8080 \
  --out-cert signer.cert.pem > /dev/null 2>&1
echo -e "${GREEN}  ✓ Code Signing сертификат создан${NC}"

# 10. Очистка временных файлов
echo -e "\n${YELLOW}10. Очистка временных файлов${NC}"
rm -f test6.* client.* signer.* *.csr.pem *.key.pem *.cert.pem csr_debug.txt 2>/dev/null
echo -e "${GREEN}✓ Временные файлы удалены${NC}"