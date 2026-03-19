#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    ПОЛНОЕ ТЕСТИРОВАНИЕ MicroPKI    ${NC}"
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

echo -e "\n${YELLOW}0. Проверка окружения${NC}"
if [ ! -f "./micropki-cli" ]; then
    echo -e "${RED}✗ micropki-cli не найден. Запустите make build${NC}"
    exit 1
fi
echo -e "${GREEN}✓ micropki-cli найден${NC}"

# 1. Настройка PKI если нужно
echo -e "\n${YELLOW}1. Проверка структуры PKI${NC}"
if [ ! -d "pki/root" ] || [ ! -d "pki/intermediate" ]; then
    echo -e "${YELLOW}  Структура PKI не найдена. Запускаем setup-pki.sh...${NC}"
    
    if [ -f "./scripts/setup-pki.sh" ]; then
        ./scripts/setup-pki.sh
        check_result "PKI настроена через setup-pki.sh"
    else
        echo -e "${RED}  ✗ Скрипт setup-pki.sh не найден!${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ Структура PKI существует${NC}"
fi

# 2. Запуск сервисов через run-all.sh
echo -e "\n${YELLOW}2. Запуск сервисов${NC}"
if [ -f "./scripts/run-all.sh" ]; then
    ./scripts/run-all.sh
    sleep 3
    echo -e "${GREEN}✓ Сервисы запущены через run-all.sh${NC}"
else
    echo -e "${RED}  ✗ Скрипт run-all.sh не найден!${NC}"
    exit 1
fi

# 3. TEST-38: Генерация CSR
echo -e "\n${YELLOW}3. TEST-38: Генерация CSR${NC}"
echo "   Команда: client gen-csr --subject ... --san dns:test38.example.com"
./micropki-cli client gen-csr \
  --subject "/CN=test38.example.com/O=Test Org/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:test38.example.com \
  --out-key test38.key.pem \
  --out-csr test38.csr.pem > /dev/null 2>&1
check_result "CSR сгенерирован"

perms=$(stat -c %a test38.key.pem 2>/dev/null || stat -f %A test38.key.pem 2>/dev/null)
if [ "$perms" = "600" ]; then
    echo -e "${GREEN}  ✓ Права ключа 0600${NC}"
else
    echo -e "${RED}  ✗ Неправильные права ключа: $perms${NC}"
fi

# 4. TEST-39: Запрос сертификата
echo -e "\n${YELLOW}4. TEST-39: Запрос сертификата${NC}"
echo "   Команда: client request-cert --csr ... --template server"
./micropki-cli client request-cert \
  --csr test38.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert test38.cert.pem > /dev/null 2>&1
check_result "Сертификат получен через HTTP API"

SERIAL=$(openssl x509 -in test38.cert.pem -noout -serial | cut -d= -f2)
echo "   Серийный номер: $SERIAL"

# 5. TEST-40: Проверка цепочки
echo -e "\n${YELLOW}5. TEST-40: Проверка цепочки сертификатов${NC}"
ROOT_CERT="./pki/root/certs/ca.cert.pem"
INTERMEDIATE_CERT="./pki/intermediate/certs/intermediate.cert.pem"
LEAF_CERT="./test38.cert.pem"

VALIDATION_OUTPUT=$(./micropki-cli client validate \
  --cert "$LEAF_CERT" \
  --untrusted "$INTERMEDIATE_CERT" \
  --trusted "$ROOT_CERT" \
  --mode full \
  --format text 2>&1)

if echo "$VALIDATION_OUTPUT" | grep -q "ПРОЙДЕНА"; then
    echo -e "${GREEN}✓ Цепочка сертификатов валидна${NC}"
else
    echo -e "${RED}✗ Ошибка валидации цепочки${NC}"
    echo "$VALIDATION_OUTPUT"
    exit 1
fi

# 6. REV-1/2/3: Проверка отзыва
echo -e "\n${YELLOW}6. REV-1/2/3: Проверка отзыва${NC}"

echo "   Проверка GOOD:"
RESULT=$(./micropki-cli client check-status \
  --cert test38.cert.pem \
  --ca-cert "$INTERMEDIATE_CERT" 2>&1)

if echo "$RESULT" | grep -q "ДЕЙСТВИТЕЛЕН"; then
    echo -e "${GREEN}    ✓ Статус GOOD${NC}"
else
    echo -e "${YELLOW}    Статус GOOD не получен (продолжаем тест)${NC}"
    echo "   Причина: $(echo "$RESULT" | grep -o "Статус:.*" || echo "неизвестно")"
fi

echo "   Отзыв сертификата..."
./micropki-cli ca revoke $SERIAL --reason keyCompromise --db-path ./pki/micropki.db --force > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    ✓ Сертификат отозван${NC}"
else
    echo -e "${RED}    ✗ Ошибка отзыва${NC}"
fi

echo "   Генерация CRL..."
./micropki-cli ca gen-crl --ca intermediate --next-update 7 --db-path ./pki/micropki.db > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    ✓ CRL сгенерирован${NC}"
else
    echo -e "${RED}    ✗ Ошибка генерации CRL${NC}"
fi

sleep 2

echo "   Проверка REVOKED:"
RESULT=$(./micropki-cli client check-status \
  --cert test38.cert.pem \
  --ca-cert "$INTERMEDIATE_CERT" 2>&1)

if echo "$RESULT" | grep -q "ОТОЗВАН"; then
    echo -e "${GREEN}    ✓ Статус REVOKED${NC}"
    echo "$RESULT" | grep -A 2 "ОТОЗВАН" | sed 's/^/      /'
else
    echo -e "${RED}    ✗ Ошибка: статус не REVOKED${NC}"
    echo "   Ответ: $RESULT"
fi

# 7. TEST-46: Построение цепочки без промежуточного
echo -e "\n${YELLOW}7. TEST-46: Построение цепочки без промежуточного${NC}"
echo "   Команда: client validate --cert test38.cert.pem --trusted $ROOT_CERT --mode chain"

VALIDATION_OUTPUT=$(./micropki-cli client validate \
  --cert test38.cert.pem \
  --trusted "$ROOT_CERT" \
  --mode chain 2>&1)
RET_CODE=$?

echo "   Результат выполнения (код $RET_CODE):"
echo "$VALIDATION_OUTPUT" | head -3 | sed 's/^/     /'

if [ $RET_CODE -ne 0 ]; then
    echo -e "${GREEN}  ✓ Цепочка не построена без промежуточного (код ошибки: $RET_CODE)${NC}"
else
    echo -e "${RED}  ✗ Цепочка построена без промежуточного (код: $RET_CODE)${NC}"
fi

# 8. Остановка сервисов через stop-all.sh
echo -e "\n${YELLOW}8. Остановка сервисов${NC}"
if [ -f "./scripts/stop-all.sh" ]; then
    ./scripts/stop-all.sh
    echo -e "${GREEN}✓ Сервисы остановлены через stop-all.sh${NC}"
else
    echo -e "${RED}  ✗ Скрипт stop-all.sh не найден!${NC}"
    exit 1
fi

# 9. Очистка временных файлов
echo -e "\n${YELLOW}9. Очистка временных файлов${NC}"
rm -f test38.* invalid.* csr_debug.txt 2>/dev/null
echo -e "${GREEN}✓ Временные файлы удалены${NC}"