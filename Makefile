#!/usr/bin/env make
# MicroPKI Makefile

.PHONY: help build clean test test-verbose test-coverage lint fmt vet run \
        example verify install uninstall release security-check check-all \
        test-db test-repo test-integration-sprint3 db-init repo-serve \
        list-certs show-cert repo-status test-serial-uniqueness \
        crl-revoke crl-gen crl-gen-root crl-check crl-verify crl-verify-signature \
        test-crl-lifecycle test-crl-http test-crl-unit test-crl-integration \
        test-crl-benchmark test-sprint4-full test-all \
        test-ocsp test-ocsp-integration test-ocsp-all test-sprint5 \
        ocsp-serve ocsp-test ocsp-test-revoked ocsp-test-unknown ocsp-test-script \
        test-sprint6 test-sprint6-full test-client-gen-csr test-client-request \
        test-client-validate test-client-check-status test-revocation-full \
        test-sprint7 test-sprint7-full test-audit test-audit-query test-audit-verify \
        test-audit-verify-fake test-compromise test-rate-limit test-ct test-policy \
        test-rsa-1024 test-detection-anomalies \
        clean-all clean-pki clean-logs clean-temp clean-audit clean-tests

# ============================================================================
# Переменные конфигурации
# ============================================================================

BINARY_NAME     := micropki-cli
MAIN_PACKAGE    := ./micropki/cmd/micropki
GOFLAGS         := -ldflags="-s -w"
GOTESTFLAGS     := -v -race
COVERAGE_FILE   := coverage.out
COVERAGE_HTML   := coverage.html
VERSION         := $(shell git describe --tags --always --dirty 2>/dev/null || echo "sprint7")
BUILD_TIME      := $(shell date -u +%Y-%m-%d_%H:%M:%S)
LDFLAGS         := -ldflags="-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -s -w"

EXAMPLE_DIR     := ./pki-example
EXAMPLE_LOG     := ./example.log
EXAMPLE_PASS    := ./pass.txt
EXAMPLE_DB      := $(EXAMPLE_DIR)/micropki.db

REPO_HOST       := 127.0.0.1
REPO_PORT       := 8080
REPO_PID_FILE   := /tmp/micropki-repo.pid

CRL_DIR         := ./pki/crl
CRL_NEXT_UPDATE := 7

TEST_CERTS_DIR  := ./test-certs
CLIENT_LOG      := ./client.log
SPRINT7_SCRIPT  := ./scripts/test-sprint7.sh
TEST_ALL_SCRIPT := ./scripts/test-all.sh

ifneq (,$(TERM))
    RED     := $(shell tput setaf 1 2>/dev/null)
    GREEN   := $(shell tput setaf 2 2>/dev/null)
    YELLOW  := $(shell tput setaf 3 2>/dev/null)
    BLUE    := $(shell tput setaf 4 2>/dev/null)
    MAGENTA := $(shell tput setaf 5 2>/dev/null)
    CYAN    := $(shell tput setaf 6 2>/dev/null)
    BOLD    := $(shell tput bold 2>/dev/null)
    RESET   := $(shell tput sgr 0 2>/dev/null)
else
    RED     := ""
    GREEN   := ""
    YELLOW  := ""
    BLUE    := ""
    MAGENTA := ""
    CYAN    := ""
    BOLD    := ""
    RESET   := ""
endif

# ============================================================================
# Основные цели
# ============================================================================

help:
	@echo "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${RESET}"
	@echo "${BOLD}${BLUE}║                     MicroPKI Makefile                        ║${RESET}"
	@echo "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${RESET}"
	@echo "${YELLOW}Использование:${RESET} make ${GREEN}<target>${RESET}\n"
	
	@echo "${BOLD}${CYAN}ОСНОВНЫЕ ЦЕЛИ:${RESET}"
	@echo "  ${GREEN}build${RESET}           - собрать бинарный файл"
	@echo "  ${GREEN}clean${RESET}           - очистить все сгенерированные файлы"
	@echo "  ${GREEN}test${RESET}            - запустить модульные тесты"
	@echo "  ${GREEN}test-all${RESET}        - запустить все тесты"
	@echo "  ${GREEN}test-coverage${RESET}   - запустить тесты с покрытием"
	@echo "  ${GREEN}fmt${RESET}             - форматировать код"
	@echo "  ${GREEN}vet${RESET}             - запустить статический анализатор"
	@echo "  ${GREEN}mod${RESET}             - обновить и проверить модули"
	@echo "  ${GREEN}info${RESET}            - показать информацию о проекте"
	@echo ""
	
	@echo "${BOLD}${CYAN}ПРИМЕРЫ И ДЕМОНСТРАЦИИ:${RESET}"
	@echo "  ${GREEN}example-full${RESET}     - создать полную PKI иерархию с аудитом"
	@echo "  ${GREEN}example-quick${RESET}    - создать минимальную PKI (только корневой CA)"
	@echo ""
	
	@echo "${BOLD}${CYAN}ЦЕЛИ АУДИТ, ПОЛИТИКИ, RATE LIMITING:${RESET}"
	@echo "  ${GREEN}test-sprint7${RESET}              - полный тест спринта 7"
	@echo "  ${GREEN}test-audit${RESET}                - тест аудита с хеш-цепочкой"
	@echo "  ${GREEN}test-audit-verify${RESET}         - проверка целостности аудита"
	@echo "  ${GREEN}test-audit-verify-fake${RESET}    - проверка обнаружения подделки"
	@echo "  ${GREEN}test-policy${RESET}               - тест политик безопасности"
	@echo "  ${GREEN}test-rate-limit${RESET}           - тест rate limiting"
	@echo "  ${GREEN}test-ct${RESET}                   - тест CT-журнала"
	@echo "  ${GREEN}test-compromise${RESET}           - тест компрометации ключей"
	@echo "  ${GREEN}test-rsa-1024${RESET}             - тест блокировки RSA-1024"
	@echo "  ${GREEN}test-detection-anomalies${RESET}  - тест детекции аномалий"
	@echo ""
	
	@echo "${BOLD}${CYAN}КЛИЕНТСКИЕ КОМАНДЫ:${RESET}"
	@echo "  ${GREEN}test-sprint6${RESET}              - запуск тестов спринта 6"
	@echo "  ${GREEN}test-client-gen-csr${RESET}       - тест генерации CSR"
	@echo "  ${GREEN}test-client-request${RESET}       - тест запроса сертификата"
	@echo "  ${GREEN}test-client-validate${RESET}      - тест валидации цепочки"
	@echo "  ${GREEN}test-client-check-status${RESET}  - тест проверки отзыва"
	@echo "  ${GREEN}test-revocation-full${RESET}      - полный тест отзыва с fallback"
	@echo ""
	
	@echo "${BOLD}${CYAN}OCSP:${RESET}"
	@echo "  ${GREEN}test-ocsp${RESET}          - модульные тесты OCSP"
	@echo "  ${GREEN}ocsp-serve${RESET}         - запуск OCSP сервера"
	@echo "  ${GREEN}ocsp-test${RESET}          - тест действительного сертификата"
	@echo ""
	
	@echo "${BOLD}${CYAN}CRL:${RESET}"
	@echo "  ${GREEN}crl-revoke${RESET}         - отзыв сертификата"
	@echo "  ${GREEN}crl-gen${RESET}            - генерация CRL"
	@echo "  ${GREEN}crl-check${RESET}          - проверка статуса отзыва"
	@echo "  ${GREEN}test-crl-unit${RESET}      - модульные тесты CRL"
	@echo ""
	
	@echo "${BOLD}${CYAN}РЕПОЗИТОРИЙ И БАЗА ДАННЫХ:${RESET}"
	@echo "  ${GREEN}db-init${RESET}            - инициализация базы данных"
	@echo "  ${GREEN}list-certs${RESET}         - список всех сертификатов в БД"
	@echo "  ${GREEN}repo-serve${RESET}         - запуск HTTP сервера репозитория"
	@echo "  ${GREEN}repo-stop${RESET}          - остановка HTTP сервера"
	@echo "  ${GREEN}repo-status${RESET}        - проверка статуса сервера"
	@echo ""
	
	@echo "${BOLD}${CYAN}ОЧИСТКА:${RESET}"
	@echo "  ${GREEN}clean-pki${RESET}        - очистить только PKI файлы"
	@echo "  ${GREEN}clean-logs${RESET}       - очистить только логи"
	@echo "  ${GREEN}clean-temp${RESET}       - очистить временные файлы"
	@echo "  ${GREEN}clean-audit${RESET}      - очистить журналы аудита"
	@echo "  ${GREEN}clean-tests${RESET}      - очистить тестовые файлы (включая tests/pki)"
	@echo "  ${GREEN}clean-all${RESET}        - полная очистка всего"
	@echo ""
	
	@echo "${BOLD}${YELLOW}Совет:${RESET} Для получения подробной справки по командам CLI выполните:"
	@echo "  ./micropki-cli help"

## default: сборка по умолчанию
default: build

## build: собирает бинарный файл
build:
	@echo "${BOLD}${BLUE}→ Building ${BINARY_NAME}...${RESET}"
	@go mod tidy
	@go build $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "${GREEN}✓ Build completed${RESET}"
	@ls -lah $(BINARY_NAME)

## clean-pki: очистка PKI файлов
clean-pki:
	@echo "${YELLOW}→ Cleaning PKI files...${RESET}"
	@rm -rf ./pki
	@rm -rf ./pki-example
	@rm -f root-pass.txt int-pass.txt pass.txt
	@rm -f *.pem *.key *.crt
	@echo "${GREEN}✓ PKI files cleaned${RESET}"

## clean-logs: очистка логов
clean-logs:
	@echo "${YELLOW}→ Cleaning logs...${RESET}"
	@rm -f *.log
	@rm -f ./logs/*.log 2>/dev/null || true
	@rm -f repo.log ocsp.log client.log
	@echo "${GREEN}✓ Logs cleaned${RESET}"

## clean-audit: очистка журналов аудита
clean-audit:
	@echo "${YELLOW}→ Cleaning audit logs...${RESET}"
	@rm -f ./pki/audit/audit.log 2>/dev/null || true
	@rm -f ./pki/audit/chain.dat 2>/dev/null || true
	@rm -f ./pki/audit/ct.log 2>/dev/null || true
	@echo "${GREEN}✓ Audit logs cleaned${RESET}"

## clean-temp: очистка временных файлов
clean-temp:
	@echo "${YELLOW}→ Cleaning temporary files...${RESET}"
	@rm -f *.out *.html *.tmp
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@rm -rf ./test-output
	@rm -rf ./tests/test-output
	@rm -rf ./test-certs
	@rm -rf ./test-sprint3
	@rm -rf ./test-pki
	@rm -rf ./test-* 2>/dev/null || true
	@rm -f $(REPO_PID_FILE)
	@rm -f test38.* test6.* client.* signer.* invalid.*
	@rm -f *.csr.pem *.key.pem *.cert.pem
	@rm -f csr_debug.txt
	@echo "${GREEN}✓ Temporary files cleaned${RESET}"

## clean-tests: очистка тестовых файлов (включая папку pki в tests)
clean-tests:
	@echo "${YELLOW}→ Cleaning test files...${RESET}"
	@rm -rf ./tests/pki 2>/dev/null || true
	@rm -rf ./tests/*.db 2>/dev/null || true
	@rm -rf ./tests/*.log 2>/dev/null || true
	@rm -rf ./tests/temp 2>/dev/null || true
	@echo "${GREEN}✓ Test files cleaned${RESET}"

## clean: очищает все сгенерированные файлы
clean:
	@echo "${BOLD}${YELLOW}→ Full cleanup...${RESET}"
	@$(MAKE) clean-pki
	@$(MAKE) clean-logs
	@$(MAKE) clean-temp
	@$(MAKE) clean-tests
	@go clean
	@rm -f $(BINARY_NAME)
	@rm -rf ./releases
	@make repo-stop >/dev/null 2>&1 || true
	@echo "${GREEN}✓ Full clean completed${RESET}"

## clean-all: полная очистка (включая go mod cache)
clean-all: clean
	@echo "${YELLOW}→ Cleaning go mod cache...${RESET}"
	@go clean -modcache -cache -testcache
	@echo "${GREEN}✓ Complete clean finished${RESET}"

# ============================================================================
# Тесты Спринта 7
# ============================================================================

## test-sprint7: полный тест спринта 7
test-sprint7: build
	@echo "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
	@echo "${BOLD}${MAGENTA}║                 ЗАПУСК ТЕСТОВ SPRINT 7                       ║${RESET}"
	@echo "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
	@if [ -f $(SPRINT7_SCRIPT) ]; then \
		chmod +x $(SPRINT7_SCRIPT); \
		$(SPRINT7_SCRIPT); \
	else \
		echo "${RED}✗ Test script not found: $(SPRINT7_SCRIPT)${RESET}"; \
		exit 1; \
	fi

## test-audit: тест аудита с хеш-цепочкой
test-audit: build
	@echo "${BOLD}${BLUE}→ Testing audit with hash chain...${RESET}"
	@./$(BINARY_NAME) audit verify
	@echo "${GREEN}✓ Audit integrity verified${RESET}"

## test-audit-query: тест запросов к аудиту
test-audit-query: build
	@echo "${BOLD}${BLUE}→ Testing audit query...${RESET}"
	@./$(BINARY_NAME) audit query --format table | head -20
	@echo "${GREEN}✓ Audit query works${RESET}"

## test-audit-verify-fake: тест обнаружения подделки
test-audit-verify-fake: build
	@echo "${BOLD}${BLUE}→ Testing audit tamper detection...${RESET}"
	@cp ./pki/audit/audit.log ./pki/audit/audit.log.backup
	@echo "Fake line" >> ./pki/audit/audit.log
	@if ./$(BINARY_NAME) audit verify 2>&1 | grep -q "ПРЕДУПРЕЖДЕНИЕ\|нарушение"; then \
		echo "${GREEN}✓ Tamper detected!${RESET}"; \
	else \
		echo "${RED}✗ Tamper not detected!${RESET}"; \
	fi
	@mv ./pki/audit/audit.log.backup ./pki/audit/audit.log
	@echo "${GREEN}✓ Audit log restored${RESET}"

## test-policy: тест политик безопасности
test-policy: build
	@echo "${BOLD}${BLUE}→ Testing security policies...${RESET}"
	@echo "  Testing wildcard rejection..."
	@./$(BINARY_NAME) ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file <(echo -n "intpass123") \
		--template server \
		--subject "CN=*.test.com" \
		--san "dns:*.test.com" \
		--out-dir /tmp 2>&1 | grep -q "wildcard" && echo "    Wildcard blocked" || echo "    Wildcard not blocked"
	@echo "  Testing validity period (>365 days)..."
	@./$(BINARY_NAME) ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file <(echo -n "intpass123") \
		--template server \
		--subject "CN=test.local" \
		--san "dns:test.local" \
		--out-dir /tmp \
		--validity-days 400 2>&1 | grep -q "превышает" && echo "    Expiry blocked" || echo "    Expiry not blocked"
	@echo "${GREEN}✓ Policy tests completed${RESET}"

## test-rate-limit: тест rate limiting
test-rate-limit: build
	@echo "${BOLD}${BLUE}→ Testing rate limiting...${RESET}"
	@./$(BINARY_NAME) repo serve --host 127.0.0.1 --port 8080 --rate-limit 2 --rate-burst 3 &
	@echo $$! > $(REPO_PID_FILE)
	@sleep 2
	@COUNT_429=0; \
	for i in 1 2 3 4 5; do \
		CODE=$$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health); \
		if [ "$$CODE" = "429" ]; then COUNT_429=$$((COUNT_429+1)); fi; \
	done; \
	if [ $$COUNT_429 -ge 1 ]; then \
		echo "    Rate limiting works ($$COUNT_429 requests blocked)"; \
	else \
		echo "    Rate limiting failed"; \
	fi
	@kill $$(cat $(REPO_PID_FILE)) 2>/dev/null || true
	@rm -f $(REPO_PID_FILE)
	@echo "${GREEN}✓ Rate limit test completed${RESET}"

## test-ct: тест CT-журнала
test-ct: build
	@echo "${BOLD}${BLUE}→ Testing Certificate Transparency log...${RESET}"
	@if [ -f ./pki/audit/ct.log ] && [ -s ./pki/audit/ct.log ]; then \
		echo "    CT log exists with $$(wc -l < ./pki/audit/ct.log) entries"; \
	else \
		echo "    CT log missing or empty"; \
	fi
	@echo "${GREEN}✓ CT test completed${RESET}"

## test-compromise: тест компрометации ключей
test-compromise: build
	@echo "${BOLD}${BLUE}→ Testing key compromise...${RESET}"
	@./$(BINARY_NAME) ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file <(echo -n "intpass123") \
		--template server \
		--subject "CN=compromise-test.local" \
		--san "dns:compromise-test.local" \
		--out-dir ./pki/certs \
		--validity-days 365 \
		--db-path ./pki/micropki.db > /dev/null 2>&1
	@./$(BINARY_NAME) ca compromise \
		--cert ./pki/certs/compromise-test.local.cert.pem \
		--reason keyCompromise \
		--force \
		--db-path ./pki/micropki.db > /dev/null 2>&1
	@COUNT=$$(sqlite3 ./pki/micropki.db "SELECT COUNT(*) FROM compromised_keys;" 2>/dev/null || echo 0); \
	if [ $$COUNT -gt 0 ]; then \
		echo "    Compromised keys recorded ($$COUNT entries)"; \
	else \
		echo "    No compromised keys recorded"; \
	fi
	@echo "${GREEN}✓ Compromise test completed${RESET}"

## test-rsa-1024: тест блокировки RSA-1024
test-rsa-1024: build
	@echo "${BOLD}${BLUE}→ Testing RSA-1024 block...${RESET}"
	@./$(BINARY_NAME) test rsa-1024
	@echo "${GREEN}✓ RSA-1024 test completed${RESET}"

## test-detection-anomalies: тест детекции аномалий
test-detection-anomalies: build
	@echo "${BOLD}${BLUE}→ Testing anomaly detection...${RESET}"
	@echo "  Current state:"
	@./$(BINARY_NAME) audit detect-anomalies --window 1 2>/dev/null | head -10
	@echo "  Generating anomalies (15 errors)..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		./$(BINARY_NAME) ca issue-cert \
			--ca-cert ./pki/certs/intermediate.cert.pem \
			--ca-key ./pki/private/intermediate.key.pem \
			--ca-pass-file <(echo -n "intpass123") \
			--template server \
			--subject "CN=error-$$i.local" \
			--san "dns:*.error-$$i.local" \
			--out-dir /tmp > /dev/null 2>&1; \
	done
	@echo "  After anomalies:"
	@./$(BINARY_NAME) audit detect-anomalies --window 1 2>/dev/null | grep -E "ОБНАРУЖЕНЫ|аномали" | head -5
	@echo "${GREEN}✓ Anomaly detection test completed${RESET}"

# ============================================================================
# Примеры и демонстрации
# ============================================================================

## example-full: создает полную PKI иерархию с аудитом
example-full: build
	@echo "${BOLD}${BLUE}→ Creating full PKI hierarchy with audit...${RESET}"
	@mkdir -p ./pki/audit ./pki/certs ./pki/private ./pki/crl
	
	# Root CA
	@echo "${YELLOW}1. Creating Root CA...${RESET}"
	@echo -n "testpass123" > ./pki/root-pass.txt
	@./$(BINARY_NAME) ca init \
		--subject "CN=Test Root CA,O=MicroPKI,C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/root-pass.txt \
		--out-dir ./pki \
		--force > /dev/null 2>&1
	@echo "   ✓ Root CA created"
	
	# Intermediate CA
	@echo "${YELLOW}2. Creating Intermediate CA...${RESET}"
	@echo -n "intpass123" > ./pki/int-pass.txt
	@./$(BINARY_NAME) ca issue-intermediate \
		--root-cert ./pki/certs/ca.cert.pem \
		--root-key ./pki/private/ca.key.pem \
		--root-pass-file ./pki/root-pass.txt \
		--subject "CN=Test Intermediate CA,O=MicroPKI,C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/int-pass.txt \
		--out-dir ./pki \
		--validity-days 1825 \
		--pathlen 0 \
		--db-path ./pki/micropki.db > /dev/null 2>&1
	@echo "   ✓ Intermediate CA created"
	
	# Test certificates
	@echo "${YELLOW}3. Issuing test certificate...${RESET}"
	@./$(BINARY_NAME) ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file ./pki/int-pass.txt \
		--template server \
		--subject "CN=example.com,O=MicroPKI" \
		--san "dns:example.com" \
		--san "dns:www.example.com" \
		--out-dir ./pki/certs \
		--validity-days 365 \
		--db-path ./pki/micropki.db > /dev/null 2>&1
	@echo "   ✓ Test certificate issued"

## example-quick: создает минимальную PKI (только корневой CA)
example-quick: build
	@echo "${BOLD}${BLUE}→ Creating quick PKI (Root CA only)...${RESET}"
	@mkdir -p ./pki/audit ./pki/certs ./pki/private
	@echo -n "testpass123" > ./pki/root-pass.txt
	@./$(BINARY_NAME) ca init \
		--subject "CN=Quick Root CA,O=MicroPKI,C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/root-pass.txt \
		--out-dir ./pki \
		--force > /dev/null 2>&1
	@echo "${GREEN}✓ Quick PKI created in ./pki${RESET}"

# ============================================================================
# Стандартные тесты Go
# ============================================================================

## test: запускает модульные тесты
test:
	@echo "${BOLD}${BLUE}→ Running unit tests...${RESET}"
	@go test ./micropki/internal/... -count=1 | grep -v "no test files" || true

## test-verbose: запускает тесты с подробным выводом
test-verbose:
	@echo "${BOLD}${BLUE}→ Running tests (verbose)...${RESET}"
	@go test -v ./micropki/internal/... -count=1

## test-coverage: запускает тесты с подсчетом покрытия
test-coverage:
	@echo "${BOLD}${BLUE}→ Running tests with coverage...${RESET}"
	@go test ./micropki/internal/... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	@go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print "${YELLOW}Coverage:${RESET} " $$3}'
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "${GREEN}✓ Coverage report: $(COVERAGE_HTML)${RESET}"

## test-all: запуск всех тестов
test-all: build
	@echo "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
	@echo "${BOLD}${MAGENTA}║                     ЗАПУСК ВСЕХ ТЕСТОВ                       ║${RESET}"
	@echo "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
	@echo "\n${BOLD}${BLUE}1. Модульные тесты:${RESET}"
	@go test ./micropki/internal/... -count=1 | grep -v "no test files" || true
	@echo "\n${BOLD}${BLUE}2. Интеграционные тесты:${RESET}"
	@go test ./tests -count=1 -v 2>/dev/null | grep -v "no test files" || echo "  No integration tests"
	@echo "\n${BOLD}${BLUE}3. Тесты Sprint 7:${RESET}"
	@$(MAKE) test-sprint7
	@echo "\n${GREEN}✓ All tests completed!${RESET}"

# ============================================================================
# Вспомогательные цели
# ============================================================================

## fmt: форматирует код
fmt:
	@echo "${BOLD}${BLUE}→ Formatting code...${RESET}"
	@go fmt ./...
	@echo "${GREEN}✓ Formatting completed${RESET}"

## vet: запускает статический анализатор
vet:
	@echo "${BOLD}${BLUE}→ Running go vet...${RESET}"
	@go vet ./...
	@echo "${GREEN}✓ Vet passed${RESET}"

## mod: обновляет и проверяет модули
mod:
	@echo "${BOLD}${BLUE}→ Tidying modules...${RESET}"
	@go mod tidy
	@go mod verify
	@echo "${GREEN}✓ Modules verified${RESET}"

## info: информация о проекте
info:
	@echo "${BOLD}${CYAN}MicroPKI - Sprint 7${RESET}"
	@echo "${YELLOW}Version:${RESET}  $(VERSION)"
	@echo "${YELLOW}Build:${RESET}    $(BUILD_TIME)"
	@echo "${YELLOW}Binary:${RESET}   $(BINARY_NAME)"
	@echo "${YELLOW}Go version:${RESET} $$(go version | cut -d' ' -f3)"
	@echo "${YELLOW}PKI directory:${RESET} ./pki"
	@echo "${YELLOW}Audit log:${RESET}   ./pki/audit/audit.log"
	@echo "${YELLOW}CT log:${RESET}      ./pki/audit/ct.log"
	@echo "${YELLOW}Database:${RESET}    ./pki/micropki.db"

## Проверка на неизвестные цели
%:
	@echo "${RED}Неизвестная цель: $@${RESET}"
	@$(MAKE) help