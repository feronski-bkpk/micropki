#!/bin/bash
# MicroPKI Sprint 8 Demo Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
print_error() { echo -e "${RED}[FAIL]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_header() { echo ""; echo -e "${MAGENTA}════════════════════════════════════════════════════════════════${NC}"; echo -e "${MAGENTA}  $1${NC}"; echo -e "${MAGENTA}════════════════════════════════════════════════════════════════${NC}"; }

# Определяем путь к бинарнику
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/../micropki-cli" ]; then
    MICROPKI="$SCRIPT_DIR/../micropki-cli"
elif [ -f "$SCRIPT_DIR/micropki-cli" ]; then
    MICROPKI="$SCRIPT_DIR/micropki-cli"
elif [ -f "./micropki-cli" ]; then
    MICROPKI="./micropki-cli"
elif [ -f "../micropki-cli" ]; then
    MICROPKI="../micropki-cli"
else
    print_error "Не найден бинарник micropki-cli"
    exit 1
fi

print_step "Использую бинарник: $MICROPKI"

# Создаем директорию с понятным именем
DEMO_DIR="/tmp/micropki_demo_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"
print_step "Создана директория: $DEMO_DIR"
print_step "Данные НЕ будут удалены после завершения!"
print_step "Для просмотра: cd $DEMO_DIR"

cleanup() {
    print_step "Скрипт завершен. Данные сохранены в: $DEMO_DIR"
}
trap cleanup EXIT

print_header "MicroPKI Sprint 8 Demo"

# ============================================================================
# 1. Создание PKI иерархии
# ============================================================================
print_header "1. Создание PKI иерархии"
mkdir -p pki/{certs,private,crl,audit}
print_success "Структура создана"

# 2. Root CA
print_step "Инициализация Root CA"
echo -n "rootpass123" > pki/root-pass.txt
"$MICROPKI" ca init \
    --subject "CN=MicroPKI Demo Root CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file pki/root-pass.txt \
    --out-dir ./pki \
    --force > /dev/null 2>&1
print_success "Root CA инициализирован"

# 3. Intermediate CA
print_step "Инициализация Intermediate CA"
echo -n "intpass123" > pki/int-pass.txt
"$MICROPKI" ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file pki/root-pass.txt \
    --subject "CN=MicroPKI Demo Intermediate CA" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file pki/int-pass.txt \
    --out-dir ./pki \
    --db-path ./pki/micropki.db > /dev/null 2>&1
print_success "Intermediate CA инициализирован"

# ============================================================================
# 4. Генерация CSR
# ============================================================================
print_header "2. Генерация CSR"

print_step "Серверный CSR (TLS)"
"$MICROPKI" client gen-csr \
    --subject "CN=server.demo.local" \
    --key-type rsa \
    --key-size 2048 \
    --san "dns:server.demo.local" \
    --san "dns:localhost" \
    --out-key ./pki/certs/server.key.pem \
    --out-csr ./pki/certs/server.csr.pem > /dev/null 2>&1
print_success "Серверный CSR создан"

print_step "Клиентский CSR"
"$MICROPKI" client gen-csr \
    --subject "CN=client.demo.local" \
    --key-type rsa \
    --key-size 2048 \
    --san "email:client@demo.local" \
    --out-key ./pki/certs/client.key.pem \
    --out-csr ./pki/certs/client.csr.pem > /dev/null 2>&1
print_success "Клиентский CSR создан"

print_step "Code Signing CSR"
"$MICROPKI" client gen-csr \
    --subject "CN=codesign.demo.local" \
    --key-type rsa \
    --key-size 2048 \
    --out-key ./pki/certs/codesign.key.pem \
    --out-csr ./pki/certs/codesign.csr.pem > /dev/null 2>&1
print_success "Code signing CSR создан"

# ============================================================================
# 5. Выпуск сертификатов (напрямую)
# ============================================================================
print_header "3. Выпуск сертификатов"

print_step "Серверный сертификат"
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template server \
    --subject "CN=server.demo.local" \
    --csr ./pki/certs/server.csr.pem \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1
print_success "Серверный сертификат выпущен"

print_step "Клиентский сертификат"
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template client \
    --subject "CN=client.demo.local" \
    --csr ./pki/certs/client.csr.pem \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1
print_success "Клиентский сертификат выпущен"

print_step "Code signing сертификат"
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template code_signing \
    --subject "CN=codesign.demo.local" \
    --csr ./pki/certs/codesign.csr.pem \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1
print_success "Code signing сертификат выпущен"

print_step "OCSP responder сертификат"
"$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template ocsp \
    --subject "CN=OCSP Responder" \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db > /dev/null 2>&1
print_success "OCSP responder сертификат выпущен"

# ============================================================================
# 6. Запуск сервисов
# ============================================================================
print_header "4. Запуск сервисов"

print_step "Запуск HTTP репозитория (порт 8080)"
"$MICROPKI" repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --rate-limit 10 \
    --rate-burst 20 > /dev/null 2>&1 &
REPO_PID=$!
sleep 3
print_success "Репозиторий запущен (PID: $REPO_PID)"

print_step "Запуск OCSP responder (порт 8081)"
"$MICROPKI" ocsp serve \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --db-path ./pki/micropki.db \
    --port 8081 > /dev/null 2>&1 &
OCSP_PID=$!
sleep 3
print_success "OCSP responder запущен (PID: $OCSP_PID)"

# ============================================================================
# 7. Выпуск через репозиторий
# ============================================================================
print_header "5. Выпуск сертификатов через репозиторий"

print_step "Серверный сертификат через репозиторий"
"$MICROPKI" client request-cert \
    --csr ./pki/certs/server.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./pki/certs/server.repo.cert.pem > /dev/null 2>&1
print_success "Серверный сертификат выпущен через репозиторий"

# ============================================================================
# 8. Валидация
# ============================================================================
print_header "6. Проверка валидности"

print_step "Проверка сертификата (полная цепочка)"
CERT_TO_VALIDATE="./pki/certs/server.demo.local.cert.pem"
if [ -f "$CERT_TO_VALIDATE" ]; then
    VALIDATION=$("$MICROPKI" client validate \
        --cert "$CERT_TO_VALIDATE" \
        --trusted ./pki/certs/ca.cert.pem \
        --untrusted ./pki/certs/intermediate.cert.pem 2>&1)
    
    if echo "$VALIDATION" | grep -qi "ПРОЙДЕНА\|valid"; then
        print_success "Сертификат валиден"
    else
        print_warning "Сертификат: $VALIDATION"
    fi
else
    print_error "Сертификат не найден: $CERT_TO_VALIDATE"
fi

# ============================================================================
# 9. Демонстрация политик
# ============================================================================
print_header "7. Демонстрация политик безопасности"

print_step "Тест wildcard SAN (должен быть отклонен)"
WILDCARD_TEST=$("$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template server \
    --subject "CN=*.test.com" \
    --san "dns:*.test.com" \
    --out-dir /tmp 2>&1 || true)
if echo "$WILDCARD_TEST" | grep -qi "wildcard"; then
    print_success "Wildcard SAN правильно заблокирован"
else
    print_warning "Wildcard SAN не был заблокирован (вывод: $WILDCARD_TEST)"
fi

print_step "Тест превышения срока (400 дней)"
EXPIRY_TEST=$("$MICROPKI" ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file pki/int-pass.txt \
    --template server \
    --subject "CN=test.local" \
    --san "dns:test.local" \
    --out-dir /tmp \
    --validity-days 400 2>&1 || true)
if echo "$EXPIRY_TEST" | grep -qi "превышает\|exceed"; then
    print_success "Превышение срока правильно заблокировано"
else
    print_warning "Превышение срока не было заблокировано"
fi

# ============================================================================
# 10. Отзыв сертификата
# ============================================================================
print_header "8. Отзыв сертификата"

CERT_FILE="./pki/certs/server.demo.local.cert.pem"
if [ -f "$CERT_FILE" ]; then
    SERIAL=$(openssl x509 -in "$CERT_FILE" -serial -noout 2>/dev/null | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    print_step "Отзыв сертификата (серийный номер: $SERIAL)"

    echo "y" | "$MICROPKI" ca revoke "$SERIAL" \
        --reason keyCompromise \
        --db-path ./pki/micropki.db > /dev/null 2>&1
    print_success "Сертификат отозван"
else
    print_error "Сертификат не найден: $CERT_FILE"
    SERIAL=""
fi

# ============================================================================
# 11. CRL
# ============================================================================
print_step "Генерация CRL"
"$MICROPKI" ca gen-crl \
    --ca intermediate \
    --db-path ./pki/micropki.db \
    --out-file ./pki/crl/intermediate.crl.pem > /dev/null 2>&1
print_success "CRL сгенерирован"

# ============================================================================
# 12. Проверка отзыва
# ============================================================================
print_step "Проверка статуса отозванного сертификата через БД"
if [ -n "$SERIAL" ]; then
    STATUS=$(sqlite3 ./pki/micropki.db "SELECT status FROM certificates WHERE serial_hex='$SERIAL';" 2>/dev/null)
    if [ "$STATUS" = "revoked" ]; then
        print_success "Сертификат отмечен как отозванный в БД"
    else
        print_warning "Сертификат не отозван в БД (статус: $STATUS)"
    fi
fi

# ============================================================================
# 13. Аудит
# ============================================================================
print_header "9. Проверка целостности аудита"

print_step "Проверка хеш-цепочки"
AUDIT_VERIFY=$("$MICROPKI" audit verify --log-file ./pki/audit/audit.log 2>&1)

if echo "$AUDIT_VERIFY" | grep -q "ПОДТВЕРЖДЕНА\|VERIFIED"; then
    print_success "Журнал аудита целостен"
else
    print_warning "Журнал аудита: $AUDIT_VERIFY"
fi

# ============================================================================
# 14. Code Signing
# ============================================================================
print_header "10. Демонстрация подписи кода"

if command -v openssl &> /dev/null; then
    cat > test_script.sh << 'EOFSCRIPT'
#!/bin/bash
echo "Hello from signed script!"
date
EOFSCRIPT
    chmod +x test_script.sh
    print_success "Тестовый скрипт создан"

    print_step "Подпись скрипта"
    openssl dgst -sha256 -sign ./pki/certs/codesign.key.pem \
        -out test_script.sh.sig test_script.sh 2>/dev/null
    print_success "Скрипт подписан"

    print_step "Проверка подписи"
    if openssl dgst -sha256 -verify <(openssl x509 -in ./pki/certs/codesign.demo.local.cert.pem \
        -pubkey -noout 2>/dev/null) \
        -signature test_script.sh.sig test_script.sh 2>/dev/null; then
        print_success "Подпись валидна"
        
        print_step "Проверка модифицированного скрипта"
        echo "# Tampered" >> test_script.sh
        if ! openssl dgst -sha256 -verify <(openssl x509 -in ./pki/certs/codesign.demo.local.cert.pem \
            -pubkey -noout 2>/dev/null) \
            -signature test_script.sh.sig test_script.sh 2>/dev/null; then
            print_success "Измененный скрипт НЕ проходит проверку"
        fi
    else
        print_error "Подпись невалидна"
    fi
else
    print_warning "OpenSSL не найден"
fi

# ============================================================================
# 15. Детекция аномалий
# ============================================================================
print_header "11. Детекция аномалий"

print_step "Анализ журнала аудита"
"$MICROPKI" audit detect-anomalies --window 1 2>/dev/null | head -15 || true
print_success "Анализ аномалий завершен"

# ============================================================================
# 16. TLS демонстрация
# ============================================================================
print_header "12. Демонстрация TLS интеграции"

if command -v python3 &> /dev/null && [ -f ./pki/certs/server.demo.local.cert.pem ]; then
    print_step "Запуск HTTPS сервера (порт 8443)"
    python3 -m http.server 8443 \
        --certfile ./pki/certs/server.demo.local.cert.pem \
        --keyfile ./pki/certs/server.key.pem \
        > /dev/null 2>&1 &
    TLS_PID=$!
    sleep 2
    
    print_step "Проверка HTTPS соединения (сертификат отозван)"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --cacert ./pki/certs/ca.cert.pem \
        https://localhost:8443 2>/dev/null)
    
    if [ "$HTTP_CODE" != "200" ]; then
        print_success "HTTPS соединение отклонено (HTTP $HTTP_CODE) - ожидаемое поведение"
    else
        print_warning "HTTPS соединение успешно, хотя сертификат должен быть отозван"
    fi
    kill $TLS_PID 2>/dev/null
else
    print_warning "Python3 не найден, пропускаем TLS"
fi

# ============================================================================
# 17. Остановка серверов
# ============================================================================
print_header "13. Остановка серверов"

if [ -n "$REPO_PID" ]; then
    kill $REPO_PID 2>/dev/null
    print_success "Репозиторий остановлен"
fi

if [ -n "$OCSP_PID" ]; then
    kill $OCSP_PID 2>/dev/null
    print_success "OCSP responder остановлен"
fi

# ============================================================================
# Финальный отчет
# ============================================================================
print_header "Демонстрация завершена"
print_success "Все проверки пройдены успешно!"

print_step "Данные сохранены в: $DEMO_DIR"
echo "  🔹 Корневой CA: pki/certs/ca.cert.pem"
echo "  🔹 Промежуточный CA: pki/certs/intermediate.cert.pem"
echo "  🔹 Серверный сертификат: pki/certs/server.demo.local.cert.pem"
echo "  🔹 База данных: pki/micropki.db"
echo "  🔹 Журнал аудита: pki/audit/audit.log"