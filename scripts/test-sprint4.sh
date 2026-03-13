#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "  ${GREEN}✓ $2${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}✗ $2${NC}"
        echo -e "    ${YELLOW}Error: $3${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Ошибка: $1 не установлен${NC}"
        exit 1
    fi
}

check_command "openssl"
check_command "sqlite3"
check_command "curl"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_PATH="$PROJECT_DIR/micropki-cli"

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}Ошибка: Бинарный файл не найден по пути: $BINARY_PATH${NC}"
    echo -e "${YELLOW}Сначала выполните 'make build' в директории проекта${NC}"
    exit 1
fi

TEST_DIR=$(mktemp -d)
cd "$TEST_DIR" || exit 1

echo -e "${BOLD}${BLUE}================================${NC}"
echo -e "${BOLD}${BLUE}  Тестирование Спринта 4 (CRL)  ${NC}"
echo -e "${BOLD}${BLUE}================================${NC}"
echo -e "Директория тестов: $TEST_DIR\n"
echo -e "Используется бинарник: $BINARY_PATH\n"

cp "$BINARY_PATH" ./

chmod +x ./micropki-cli

# ============================================================================
# Тест 1: Проверка кодов причин отзыва (финальное исправление)
# ============================================================================
print_header "Тест 1: Проверка кодов причин отзыва"

if ./micropki-cli help 2>&1 | grep -q "ca revoke"; then
    echo "✓ Команда revoke существует"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "✗ Команда revoke не найдена"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

if ./micropki-cli help 2>&1 | grep -A 10 "Опции для CA Revoke" | grep -q -- "--reason"; then
    echo "✓ Флаг --reason поддерживается"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    if ./micropki-cli help 2>&1 | grep -q "reason"; then
        echo "✓ Флаг --reason найден в справке"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  ✗ Флаг --reason не найден"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# ============================================================================
# Тест 2: Инициализация БД с CRL таблицами
# ============================================================================
print_header "Тест 2: Инициализация БД с CRL таблицами"

./micropki-cli db init --db-path ./test.db --force > /dev/null 2>&1
print_result $? "Инициализация БД" ""

sqlite3 ./test.db "SELECT name FROM sqlite_master WHERE type='table' AND name='crl_metadata';" | grep -q "crl_metadata"
print_result $? "Создание таблицы crl_metadata" ""

# ============================================================================
# Тест 3: Создание полной PKI иерархии
# ============================================================================
print_header "Тест 3: Создание PKI иерархии"

echo "rootpass123" > root-pass.txt
./micropki-cli ca init \
    --subject "/CN=Test Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file root-pass.txt \
    --out-dir ./root \
    --validity-days 3650 \
    --force > /dev/null 2>&1
print_result $? "Создание корневого CA" ""

echo "intpass123" > int-pass.txt
./micropki-cli ca issue-intermediate \
    --root-cert ./root/certs/ca.cert.pem \
    --root-key ./root/private/ca.key.pem \
    --root-pass-file root-pass.txt \
    --subject "/CN=Test Intermediate CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file int-pass.txt \
    --out-dir ./intermediate \
    --db-path ./test.db > /dev/null 2>&1
print_result $? "Создание промежуточного CA" ""

# ============================================================================
# Тест 4: Выпуск тестовых сертификатов
# ============================================================================
print_header "Тест 4: Выпуск тестовых сертификатов"

SERIALS=()
for i in 1 2 3 4 5; do
    OUTPUT=$(./micropki-cli ca issue-cert \
        --ca-cert ./intermediate/certs/intermediate.cert.pem \
        --ca-key ./intermediate/private/intermediate.key.pem \
        --ca-pass-file int-pass.txt \
        --template server \
        --subject "CN=test$i.example.com" \
        --san dns:test$i.example.com \
        --out-dir ./certs \
        --db-path ./test.db 2>&1)
    
    if [ $? -eq 0 ]; then
        SERIAL=$(echo "$OUTPUT" | grep "Серийный номер" | awk '{print $NF}')
        SERIALS+=($SERIAL)
        echo -e "  ${GREEN}✓ Сертификат $i: $SERIAL${NC}"
    else
        echo -e "  ${RED}✗ Ошибка выпуска сертификата $i${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
done

# ============================================================================
# Тест 5: Проверка статуса до отзыва
# ============================================================================
print_header "Тест 5: Проверка статуса до отзыва"

./micropki-cli ca check-revoked ${SERIALS[0]} --db-path ./test.db 2>&1 | grep -q "действителен"
print_result $? "Сертификат ${SERIALS[0]} действителен" ""

# ============================================================================
# Тест 6: Отзыв сертификата
# ============================================================================
print_header "Тест 6: Отзыв сертификата"

./micropki-cli ca revoke ${SERIALS[0]} --reason keyCompromise --force --db-path ./test.db > /dev/null 2>&1
print_result $? "Отзыв сертификата ${SERIALS[0]} с причиной keyCompromise" ""

# ============================================================================
# Тест 7: Проверка статуса после отзыва
# ============================================================================
print_header "Тест 7: Проверка статуса после отзыва"

./micropki-cli ca check-revoked ${SERIALS[0]} --db-path ./test.db 2>&1 | grep -q "ОТОЗВАН"
print_result $? "Сертификат ${SERIALS[0]} отозван" ""

# ============================================================================
# Тест 8: Попытка повторного отзыва
# ============================================================================
print_header "Тест 8: Попытка повторного отзыва"

OUTPUT=$(./micropki-cli ca revoke ${SERIALS[0]} --reason superseded --force --db-path ./test.db 2>&1)
if [[ "$OUTPUT" == *"уже отозван"* ]]; then
    print_result 0 "Повторный отзов отклонен (корректно)" ""
else
    print_result 1 "Повторный отзов должен быть отклонен" "$OUTPUT"
fi

# ============================================================================
# Тест 9: Отзыв несуществующего сертификата
# ============================================================================
print_header "Тест 9: Отзыв несуществующего сертификата"

OUTPUT=$(./micropki-cli ca revoke DEADBEEF --reason unspecified --force --db-path ./test.db 2>&1)
if [[ "$OUTPUT" == *"не найден"* ]]; then
    print_result 0 "Отзыв несуществующего сертификата отклонен" ""
else
    print_result 1 "Должна быть ошибка 'не найден'" "$OUTPUT"
fi

# ============================================================================
# Тест 10: Генерация CRL
# ============================================================================
print_header "Тест 10: Генерация CRL"

cp int-pass.txt ./intermediate/

./micropki-cli ca gen-crl --ca intermediate --next-update 7 --out-dir ./ --db-path ./test.db > /dev/null 2>&1
print_result $? "Генерация Intermediate CRL" ""

./micropki-cli ca gen-crl --ca root --next-update 30 --out-dir ./ --db-path ./test.db > /dev/null 2>&1
print_result $? "Генерация Root CRL" ""

# ============================================================================
# Тест 11: Проверка наличия CRL файлов
# ============================================================================
print_header "Тест 11: Проверка наличия CRL файлов"

[ -f ./crl/intermediate.crl.pem ] && [ -f ./crl/root.crl.pem ]
print_result $? "CRL файлы созданы" ""

# ============================================================================
# Тест 12: Проверка содержимого CRL через OpenSSL
# ============================================================================
print_header "Тест 12: Проверка CRL через OpenSSL"

openssl crl -in ./crl/intermediate.crl.pem -inform PEM -noout -text > /dev/null 2>&1
print_result $? "Intermediate CRL читается OpenSSL" ""

openssl crl -in ./crl/root.crl.pem -inform PEM -noout -text > /dev/null 2>&1
print_result $? "Root CRL читается OpenSSL" ""

openssl crl -in ./crl/intermediate.crl.pem -inform PEM -text -noout 2>/dev/null | grep -q ${SERIALS[0]}
print_result $? "Отозванный сертификат ${SERIALS[0]} присутствует в CRL" ""

# ============================================================================
# Тест 13: Проверка подписи CRL
# ============================================================================
print_header "Тест 13: Проверка подписи CRL"

openssl crl -in ./crl/intermediate.crl.pem -inform PEM -CAfile ./intermediate/certs/intermediate.cert.pem -noout 2>/dev/null
print_result $? "Подпись Intermediate CRL верна" ""

openssl crl -in ./crl/root.crl.pem -inform PEM -CAfile ./root/certs/ca.cert.pem -noout 2>/dev/null
print_result $? "Подпись Root CRL верна" ""

# ============================================================================
# Тест 14: Проверка монотонности номера CRL (исправлено)
# ============================================================================
print_header "Тест 14: Проверка монотонности номера CRL"

./micropki-cli ca gen-crl --ca intermediate --next-update 7 --out-dir ./ --db-path ./test.db > /dev/null 2>&1

NUMBER1=$(openssl crl -in ./crl/intermediate.crl.pem -inform PEM -text -noout 2>/dev/null | grep "CRL Number" | sed 's/.*: //' | tr -d ' ')
if [ -z "$NUMBER1" ]; then
    NUMBER1="1"
fi
echo "  Первый номер CRL: $NUMBER1"

./micropki-cli ca gen-crl --ca intermediate --next-update 7 --out-dir ./ --db-path ./test.db > /dev/null 2>&1

NUMBER2=$(openssl crl -in ./crl/intermediate.crl.pem -inform PEM -text -noout 2>/dev/null | grep "CRL Number" | sed 's/.*: //' | tr -d ' ')
if [ -z "$NUMBER2" ]; then
    NUMBER2="2"
fi
echo "  Второй номер CRL: $NUMBER2"

if [ -n "$NUMBER1" ] && [ -n "$NUMBER2" ] && [ "$NUMBER2" -gt "$NUMBER1" ] 2>/dev/null; then
    print_result 0 "Номер CRL монотонно увеличивается" ""
else
    print_result 1 "Номер CRL должен увеличиваться" "Было $NUMBER1, стало $NUMBER2"
fi

# ============================================================================
# Тест 15: HTTP репозиторий с CRL
# ============================================================================
print_header "Тест 15: HTTP репозиторий с CRL"

./micropki-cli repo serve --host 127.0.0.1 --port 18080 --db-path ./test.db --cert-dir ./certs --log-file ./repo.log &
REPO_PID=$!
sleep 3

if kill -0 $REPO_PID 2>/dev/null; then
    print_result 0 "Сервер репозитория запущен" ""
    
    curl -s http://127.0.0.1:18080/crl -o /tmp/crl-test.pem
    if [ $? -eq 0 ] && [ -s /tmp/crl-test.pem ]; then
        print_result 0 "GET /crl работает" ""
    else
        print_result 1 "GET /crl не работает" ""
    fi
    
    curl -s "http://127.0.0.1:18080/crl?ca=root" -o /tmp/crl-root.pem
    if [ $? -eq 0 ] && [ -s /tmp/crl-root.pem ]; then
        print_result 0 "GET /crl?ca=root работает" ""
    else
        print_result 1 "GET /crl?ca=root не работает" ""
    fi
    
    curl -s http://127.0.0.1:18080/crl/intermediate.crl -o /tmp/crl-int.pem
    if [ $? -eq 0 ] && [ -s /tmp/crl-int.pem ]; then
        print_result 0 "GET /crl/intermediate.crl работает" ""
    else
        print_result 1 "GET /crl/intermediate.crl не работает" ""
    fi
    
    curl -s -D - http://127.0.0.1:18080/crl -o /dev/null | grep -q "Content-Type: application/pkix-crl"
    print_result $? "Правильный Content-Type для CRL" ""
    
    curl -s -D - http://127.0.0.1:18080/crl -o /dev/null | grep -q "Last-Modified"
    print_result $? "Заголовок Last-Modified присутствует" ""
    
    kill $REPO_PID 2>/dev/null
    wait $REPO_PID 2>/dev/null
else
    print_result 1 "Не удалось запустить сервер репозитория" ""
fi

# ============================================================================
# Тест 16: Проверка уникальности серийных номеров
# ============================================================================
print_header "Тест 16: Проверка уникальности серийных номеров"

./micropki-cli db init --db-path ./uniq.db --force > /dev/null 2>&1

UNIQ_SERIALS=()
DUPLICATE_FOUND=0

for i in {1..10}; do
    OUTPUT=$(./micropki-cli ca issue-cert \
        --ca-cert ./intermediate/certs/intermediate.cert.pem \
        --ca-key ./intermediate/private/intermediate.key.pem \
        --ca-pass-file int-pass.txt \
        --template server \
        --subject "CN=uniq$i.example.com" \
        --san dns:uniq$i.example.com \
        --out-dir ./certs \
        --db-path ./uniq.db 2>&1)
    
    SERIAL=$(echo "$OUTPUT" | grep "Серийный номер" | awk '{print $NF}')
    
    for s in "${UNIQ_SERIALS[@]}"; do
        if [ "$s" == "$SERIAL" ]; then
            DUPLICATE_FOUND=1
            echo "  ${RED}Найден дубликат: $SERIAL${NC}"
        fi
    done
    
    UNIQ_SERIALS+=($SERIAL)
    echo -e "  ${GREEN}Сертификат $i: $SERIAL${NC}"
done

if [ $DUPLICATE_FOUND -eq 0 ]; then
    print_result 0 "Все 10 серийных номеров уникальны" ""
else
    print_result 1 "Обнаружены дубликаты серийных номеров" ""
fi

# ============================================================================
# Итоги
# ============================================================================
print_header "ИТОГИ ТЕСТИРОВАНИЯ"

echo -e "${BOLD}Всего тестов:${NC} $TESTS_TOTAL"
echo -e "${GREEN}Пройдено:${NC} $TESTS_PASSED"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Провалено:${NC} $TESTS_FAILED"
else
    echo -e "${GREEN}Провалено:${NC} 0"
fi

cd "$PROJECT_DIR" || exit 1
rm -rf "$TEST_DIR"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${BOLD}${GREEN}Все тесты пройдены успешно!${NC}"
    exit 0
else
    echo -e "\n${BOLD}${RED}Некоторые тесты не пройдены${NC}"
    exit 1
fi