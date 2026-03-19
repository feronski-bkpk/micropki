#!/bin/bash
# Тестовый скрипт для проверки требований Спринта 3

set -e

BINARY="./micropki-cli"
TEST_DIR="./test-sprint3"
DB_PATH="$TEST_DIR/micropki.db"
CERT_DIR="$TEST_DIR/certs"
ROOT_PASS="$TEST_DIR/root-pass.txt"
INT_PASS="$TEST_DIR/int-pass.txt"
PORT=8181

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Тестирование Спринта 3: Интеграция с БД и Репозиторий ===${NC}"

rm -rf $TEST_DIR
mkdir -p $TEST_DIR

check_port() {
    if lsof -i:$PORT > /dev/null 2>&1; then
        echo -e "${RED}Порт $PORT уже занят!${NC}"
        exit 1
    fi
}

# 1. Тест инициализации БД
echo -e "\n${YELLOW}1. Тест инициализации БД (CLI-12)${NC}"
$BINARY db init --db-path $DB_PATH
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}✓ База данных создана${NC}"
else
    echo -e "${RED}✗ База данных не создана${NC}"
    exit 1
fi

$BINARY db init --db-path $DB_PATH 2>&1 | grep -q "already exists" && echo -e "${GREEN}✓ Команда идемпотентна${NC}"

# 2. Создание корневого CA
echo -e "\n${YELLOW}2. Создание корневого CA${NC}"
echo "rootpass123" > $ROOT_PASS
$BINARY ca init \
    --subject "/CN=Test Root CA/O=MicroPKI Test/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file $ROOT_PASS \
    --out-dir $TEST_DIR/root \
    --validity-days 365

# 3. Создание промежуточного CA
echo -e "\n${YELLOW}3. Создание промежуточного CA (PKI-14)${NC}"
echo "intpass123" > $INT_PASS
$BINARY ca issue-intermediate \
    --root-cert $TEST_DIR/root/certs/ca.cert.pem \
    --root-key $TEST_DIR/root/private/ca.key.pem \
    --root-pass-file $ROOT_PASS \
    --subject "/CN=Test Intermediate CA/O=MicroPKI Test/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file $INT_PASS \
    --out-dir $TEST_DIR/intermediate \
    --db-path $DB_PATH

# 4. Выпуск тестовых сертификатов
echo -e "\n${YELLOW}4. Выпуск тестовых сертификатов (TEST-13)${NC}"
CERT_FILES=()
for i in {1..5}; do
    OUTPUT=$($BINARY ca issue-cert \
        --ca-cert $TEST_DIR/intermediate/certs/intermediate.cert.pem \
        --ca-key $TEST_DIR/intermediate/private/intermediate.key.pem \
        --ca-pass-file $INT_PASS \
        --template server \
        --subject "CN=test$i.example.com" \
        --san dns:test$i.example.com \
        --out-dir $TEST_DIR/certs \
        --db-path $DB_PATH 2>&1)
    
    SERIAL=$(echo "$OUTPUT" | grep "Серийный номер" | awk '{print $NF}')
    CERT_FILES+=("$TEST_DIR/certs/test$i.example.com.cert.pem")
    echo -e "${GREEN}  ✓ Сертификат $i выпущен: $SERIAL${NC}"
done

# 5. Тест CLI: ca list-certs
echo -e "\n${YELLOW}5. Тест ca list-certs (CLI-13)${NC}"
$BINARY ca list-certs --db-path $DB_PATH --format table | head -20

# 6. Тест CLI: ca show-cert
echo -e "\n${YELLOW}6. Тест ca show-cert (CLI-14)${NC}"
SERIAL=$($BINARY ca list-certs --db-path $DB_PATH --format json | jq -r '.[0].serial_hex')
echo "Первый серийный номер: $SERIAL"
$BINARY ca show-cert $SERIAL --db-path $DB_PATH --format pem | head -10

# 7. Запуск сервера репозитория
echo -e "\n${YELLOW}7. Запуск сервера репозитория на порту $PORT (CLI-15)${NC}"
check_port
$BINARY repo serve \
    --host 127.0.0.1 \
    --port $PORT \
    --db-path $DB_PATH \
    --cert-dir $TEST_DIR/certs \
    --log-file $TEST_DIR/repo.log &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Сервер не запустился${NC}"
    exit 1
fi

# 8. Тест API: получение сертификата
echo -e "\n${YELLOW}8. Тест API /certificate/<serial> (REPO-2)${NC}"
curl -s http://127.0.0.1:$PORT/certificate/$SERIAL -o $TEST_DIR/fetched.pem

if [ -f "${CERT_FILES[0]}" ]; then
    if diff "${CERT_FILES[0]}" $TEST_DIR/fetched.pem >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Сертификат успешно получен и совпадает${NC}"
    else
        echo -e "${RED}✗ Полученный сертификат не совпадает${NC}"
        echo "  Ожидаемый файл: ${CERT_FILES[0]}"
        echo "  Полученный файл: $TEST_DIR/fetched.pem"
    fi
fi

# 9. Тест API: получение CA сертификатов
echo -e "\n${YELLOW}9. Тест API /ca/root и /ca/intermediate (REPO-3)${NC}"
curl -s http://127.0.0.1:$PORT/ca/root -o $TEST_DIR/root-fetched.pem
curl -s http://127.0.0.1:$PORT/ca/intermediate -o $TEST_DIR/int-fetched.pem

if diff $TEST_DIR/root/certs/ca.cert.pem $TEST_DIR/root-fetched.pem >/dev/null; then
    echo -e "${GREEN}✓ Root CA успешно получен${NC}"
else
    echo -e "${RED}✗ Root CA не совпадает${NC}"
fi

if diff $TEST_DIR/intermediate/certs/intermediate.cert.pem $TEST_DIR/int-fetched.pem >/dev/null; then
    echo -e "${GREEN}✓ Intermediate CA успешно получен${NC}"
else
    echo -e "${RED}✗ Intermediate CA не совпадает${NC}"
fi

# 10. Тест CRL
echo -e "\n${YELLOW}10. Тест CRL эндпоинта${NC}"
$BINARY ca gen-crl --ca intermediate --next-update 7 --db-path $DB_PATH --out-dir $TEST_DIR > /dev/null 2>&1

curl -s http://127.0.0.1:$PORT/crl -o $TEST_DIR/crl-fetched.pem
if [ -s "$TEST_DIR/crl-fetched.pem" ]; then
    echo -e "${GREEN}✓ CRL успешно получен через API${NC}"
else
    echo -e "${RED}✗ CRL не получен${NC}"
fi

# 11. Негативные тесты
echo -e "\n${YELLOW}11. Негативные тесты${NC}"
STATUS=$(curl -s -w "%{http_code}" http://127.0.0.1:$PORT/certificate/XYZ -o /dev/null)
[ "$STATUS" -eq 400 ] && echo -e "${GREEN}✓ Неверный hex -> 400 Bad Request${NC}" || echo -e "${RED}✗ Ожидался 400, получен $STATUS${NC}"

STATUS=$(curl -s -w "%{http_code}" http://127.0.0.1:$PORT/certificate/1234567890abcdef -o /dev/null)
[ "$STATUS" -eq 404 ] && echo -e "${GREEN}✓ Несуществующий сертификат -> 404 Not Found${NC}" || echo -e "${RED}✗ Ожидался 404, получен $STATUS${NC}"

kill $SERVER_PID 2>/dev/null || true

# 12. Тест уникальности серийных номеров
echo -e "\n${YELLOW}12. Тест уникальности серийных номеров (TEST-17)${NC}"
declare -A SERIALS
DUPLICATE_FOUND=0

for i in {1..10}; do
    OUTPUT=$($BINARY ca issue-cert \
        --ca-cert $TEST_DIR/intermediate/certs/intermediate.cert.pem \
        --ca-key $TEST_DIR/intermediate/private/intermediate.key.pem \
        --ca-pass-file $INT_PASS \
        --template server \
        --subject "CN=uniqueness$i.example.com" \
        --out-dir $TEST_DIR/certs \
        --db-path $DB_PATH 2>&1)
    
    SERIAL=$(echo "$OUTPUT" | grep "Серийный номер" | awk '{print $NF}')
    
    if [ -z "$SERIAL" ]; then
        echo -e "${RED}  ✗ Не удалось получить серийный номер для сертификата $i${NC}"
        continue
    fi
    
    if [ -n "${SERIALS[$SERIAL]}" ]; then
        echo -e "${RED}  ✗ Обнаружен дубликат серийного номера: $SERIAL${NC}"
        DUPLICATE_FOUND=1
    else
        SERIALS[$SERIAL]=1
        echo -e "${GREEN}  ✓ Сертификат $i: $SERIAL${NC}"
    fi
done

if [ $DUPLICATE_FOUND -eq 0 ]; then
    echo -e "${GREEN}✓ Все 10 серийных номеров уникальны${NC}"
else
    echo -e "${RED}✗ Обнаружены дубликаты серийных номеров${NC}"
fi

# Очистка
rm -rf $TEST_DIR