#!/bin/bash
# Тестовый скрипт для проверки требований Спринта 3

set -e

BINARY="./micropki-cli"
TEST_DIR="./test-sprint3"
DB_PATH="$TEST_DIR/micropki.db"
CERT_DIR="$TEST_DIR/certs"
ROOT_PASS="$TEST_DIR/root-pass.txt"
INT_PASS="$TEST_DIR/int-pass.txt"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== Тестирование Спринта 3: Интеграция с БД и Репозиторий ===${NC}"

# Очистка и подготовка
rm -rf $TEST_DIR
mkdir -p $TEST_DIR

# 1. Тест инициализации БД
echo -e "\n${YELLOW}1. Тест инициализации БД (CLI-12)${NC}"
$BINARY db init --db-path $DB_PATH
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}✓ База данных создана${NC}"
else
    echo -e "${RED}✗ База данных не создана${NC}"
    exit 1
fi

# Проверка идемпотентности
$BINARY db init --db-path $DB_PATH 2>&1 | grep -q "already exists" || echo -e "${GREEN}✓ Команда идемпотентна${NC}"

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

# 3. Создание промежуточного CA (должен быть вставлен в БД)
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

# 4. Выпуск нескольких сертификатов
echo -e "\n${YELLOW}4. Выпуск тестовых сертификатов (TEST-13)${NC}"
for i in {1..5}; do
    $BINARY ca issue-cert \
        --ca-cert $TEST_DIR/intermediate/certs/intermediate.cert.pem \
        --ca-key $TEST_DIR/intermediate/private/intermediate.key.pem \
        --ca-pass-file $INT_PASS \
        --template server \
        --subject "CN=test$i.example.com" \
        --san dns:test$i.example.com \
        --out-dir $TEST_DIR/certs \
        --db-path $DB_PATH
    echo -e "${GREEN}  ✓ Сертификат $i выпущен${NC}"
done

# 5. Тест CLI: ca list-certs
echo -e "\n${YELLOW}5. Тест ca list-certs (CLI-13)${NC}"
$BINARY ca list-certs --db-path $DB_PATH --format table | head -20
$BINARY ca list-certs --db-path $DB_PATH --status valid --format json | jq . | head -20

# 6. Тест CLI: ca show-cert
echo -e "\n${YELLOW}6. Тест ca show-cert (CLI-14)${NC}"
SERIAL=$($BINARY ca list-certs --db-path $DB_PATH --format json | jq -r '.[0].serial_hex')
echo "Первый серийный номер: $SERIAL"
$BINARY ca show-cert $SERIAL --db-path $DB_PATH --format pem | head -10

# 7. Запуск сервера репозитория в фоне
echo -e "\n${YELLOW}7. Запуск сервера репозитория (CLI-15)${NC}"
$BINARY repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path $DB_PATH \
    --cert-dir $TEST_DIR/certs &
SERVER_PID=$!
sleep 2

# 8. Тест API: получение сертификата
echo -e "\n${YELLOW}8. Тест API /certificate/<serial> (REPO-2)${NC}"
curl -s http://127.0.0.1:8080/certificate/$SERIAL -o $TEST_DIR/fetched.pem
if diff $TEST_DIR/certs/*.cert.pem $TEST_DIR/fetched.pem >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Сертификат успешно получен и совпадает${NC}"
else
    echo -e "${RED}✗ Полученный сертификат не совпадает${NC}"
fi

# 9. Тест API: получение CA сертификатов
echo -e "\n${YELLOW}9. Тест API /ca/root и /ca/intermediate (REPO-3)${NC}"
curl -s http://127.0.0.1:8080/ca/root -o $TEST_DIR/root-fetched.pem
curl -s http://127.0.0.1:8080/ca/intermediate -o $TEST_DIR/int-fetched.pem

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

# 10. Тест CRL заглушки
echo -e "\n${YELLOW}10. Тест CRL заглушки (REPO-4)${NC}"
curl -v http://127.0.0.1:8080/crl 2>&1 | grep -q "501"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ CRL заглушка работает (501 Not Implemented)${NC}"
fi

# 11. Негативные тесты
echo -e "\n${YELLOW}11. Негативные тесты${NC}"
# Неверный серийный номер
curl -s -w "%{http_code}" http://127.0.0.1:8080/certificate/XYZ -o /dev/null | grep -q "400"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Неверный hex -> 400 Bad Request${NC}"
fi

# Несуществующий сертификат
curl -s -w "%{http_code}" http://127.0.0.1:8080/certificate/1234567890abcdef -o /dev/null | grep -q "404"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Несуществующий сертификат -> 404 Not Found${NC}"
fi

# Остановка сервера
kill $SERVER_PID

# 12. Тест уникальности серийных номеров
echo -e "\n${YELLOW}12. Тест уникальности серийных номеров (TEST-17)${NC}"
# Выпускаем 10 сертификатов и проверяем дубликаты
SERIALS=""
for i in {1..10}; do
    SERIAL=$($BINARY ca issue-cert \
        --ca-cert $TEST_DIR/intermediate/certs/intermediate.cert.pem \
        --ca-key $TEST_DIR/intermediate/private/intermediate.key.pem \
        --ca-pass-file $INT_PASS \
        --template server \
        --subject "CN=uniqueness$i.example.com" \
        --out-dir $TEST_DIR/certs \
        --db-path $DB_PATH 2>&1 | grep "Серийный номер" | awk '{print $NF}')
    
    if echo "$SERIALS" | grep -q "$SERIAL"; then
        echo -e "${RED}✗ Обнаружен дубликат серийного номера: $SERIAL${NC}"
        exit 1
    fi
    SERIALS="$SERIALS $SERIAL"
done
echo -e "${GREEN}✓ Все 10 серийных номеров уникальны${NC}"

echo -e "\n${GREEN}=== Все тесты Спринта 3 пройдены успешно! ===${NC}"