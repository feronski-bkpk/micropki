#!/usr/bin/env make
# MicroPKI Makefile - Спринт 6

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
        clean-all clean-pki clean-logs clean-temp

# ============================================================================
# Переменные конфигурации
# ============================================================================

BINARY_NAME     := micropki-cli
MAIN_PACKAGE    := ./micropki/cmd/micropki
GOFLAGS         := -ldflags="-s -w"
GOTESTFLAGS     := -v -race
COVERAGE_FILE   := coverage.out
COVERAGE_HTML   := coverage.html
VERSION         := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
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
SPRINT6_SCRIPT  := ./scripts/test-sprint6.sh
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
	@echo "  ${GREEN}test-all${RESET}        - запустить все тесты (спринты 1-6)"
	@echo "  ${GREEN}example-full${RESET}    - создать полную PKI иерархию"
	@echo ""
	
	@echo "${BOLD}${CYAN}ЦЕЛИ СПРИНТА 6 (КЛИЕНТ):${RESET}"
	@echo "  ${GREEN}test-sprint6${RESET}             - запустить тесты спринта 6"
	@echo "  ${GREEN}test-client-gen-csr${RESET}      - тест генерации CSR"
	@echo "  ${GREEN}test-client-request${RESET}      - тест запроса сертификата"
	@echo "  ${GREEN}test-client-validate${RESET}     - тест валидации цепочки"
	@echo "  ${GREEN}test-client-check-status${RESET} - тест проверки отзыва"
	@echo "  ${GREEN}test-revocation-full${RESET}     - полный тест отзыва с fallback"
	@echo ""
	
	@echo "${BOLD}${CYAN}ЦЕЛИ СПРИНТА 5 (OCSP):${RESET}"
	@echo "  ${GREEN}ocsp-serve${RESET}       - запуск OCSP сервера"
	@echo "  ${GREEN}ocsp-test${RESET}        - тест действительного сертификата"
	@echo "  ${GREEN}test-ocsp${RESET}        - модульные тесты OCSP"
	@echo ""
	
	@echo "${BOLD}${CYAN}ЦЕЛИ СПРИНТА 4 (CRL):${RESET}"
	@echo "  ${GREEN}crl-revoke${RESET}       - отзыв сертификата"
	@echo "  ${GREEN}crl-gen${RESET}          - генерация CRL"
	@echo "  ${GREEN}crl-check${RESET}        - проверка статуса отзыва"
	@echo ""
	
	@echo "${BOLD}${CYAN}ЦЕЛИ СПРИНТА 3 (РЕПОЗИТОРИЙ):${RESET}"
	@echo "  ${GREEN}repo-serve${RESET}       - запуск HTTP сервера"
	@echo "  ${GREEN}repo-stop${RESET}        - остановка HTTP сервера"
	@echo "  ${GREEN}repo-status${RESET}      - проверка статуса сервера"
	@echo ""
	
	@echo "${BOLD}${CYAN}ОЧИСТКА:${RESET}"
	@echo "  ${GREEN}clean-pki${RESET}        - очистить только PKI файлы"
	@echo "  ${GREEN}clean-logs${RESET}       - очистить только логи"
	@echo "  ${GREEN}clean-temp${RESET}       - очистить временные файлы"
	@echo "  ${GREEN}clean-all${RESET}        - полная очистка всего"

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

## clean: очищает все сгенерированные файлы
clean:
	@echo "${BOLD}${YELLOW}→ Full cleanup...${RESET}"
	@$(MAKE) clean-pki
	@$(MAKE) clean-logs
	@$(MAKE) clean-temp
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

## test: запускает тесты
test:
	@echo "${BOLD}${BLUE}→ Running unit tests...${RESET}"
	@go test ./micropki/internal/... -count=1 | grep -v "no test files"

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

# ============================================================================
# Цели Спринта 6 (Клиентские команды)
# ============================================================================

## test-sprint6: запуск тестов спринта 6
test-sprint6: build
	@echo "${BOLD}${BLUE}→ Running Sprint 6 tests...${RESET}"
	@chmod +x $(SPRINT6_SCRIPT) 2>/dev/null || (mkdir -p ./scripts && touch $(SPRINT6_SCRIPT))
	@$(SPRINT6_SCRIPT)

## test-client-gen-csr: тест генерации CSR
test-client-gen-csr: build
	@echo "${BOLD}${BLUE}→ Testing client gen-csr...${RESET}"
	@mkdir -p $(TEST_CERTS_DIR)
	@./$(BINARY_NAME) client gen-csr \
		--subject "/CN=test-sprint6.example.com/O=Test/C=RU" \
		--key-type rsa \
		--key-size 2048 \
		--san dns:test-sprint6.example.com \
		--san dns:api-sprint6.example.com \
		--out-key $(TEST_CERTS_DIR)/test.key.pem \
		--out-csr $(TEST_CERTS_DIR)/test.csr.pem
	@echo "${GREEN}✓ CSR generated successfully${RESET}"
	@ls -la $(TEST_CERTS_DIR)/

## test-client-request: тест запроса сертификата
test-client-request: build
	@echo "${BOLD}${BLUE}→ Testing client request-cert...${RESET}"
	@echo "${YELLOW}Note: Repository server must be running (make repo-serve)${RESET}"

## test-client-validate: тест валидации цепочки
test-client-validate: build
	@echo "${BOLD}${BLUE}→ Testing client validate...${RESET}"
	@echo "${YELLOW}Note: Run after test-client-request${RESET}"

## test-client-check-status: тест проверки отзыва
test-client-check-status: build
	@echo "${BOLD}${BLUE}→ Testing client check-status...${RESET}"
	@echo "${YELLOW}Note: OCSP server must be running (make ocsp-serve)${RESET}"

## test-revocation-full: полный тест отзыва с fallback
test-revocation-full: build
	@echo "${BOLD}${BLUE}→ Testing full revocation with fallback...${RESET}"
	@./scripts/test-revocation.sh 2>/dev/null || echo "${YELLOW}Test script not found${RESET}"

# ============================================================================
# Цели для Спринта 3 (База данных и Репозиторий)
# ============================================================================

## db-init: инициализация базы данных
db-init:
	@echo "${BOLD}${BLUE}→ Initializing database...${RESET}"
	@mkdir -p ./pki
	@./$(BINARY_NAME) db init --db-path ./pki/micropki.db --force
	@echo "${GREEN}✓ Database initialized at ./pki/micropki.db${RESET}"

## list-certs: список всех сертификатов в БД
list-certs:
	@echo "${BOLD}${BLUE}→ Listing certificates from database...${RESET}"
	@./$(BINARY_NAME) ca list-certs --db-path ./pki/micropki.db --format table

## repo-serve: запуск HTTP сервера репозитория
repo-serve:
	@echo "${BOLD}${BLUE}→ Starting repository server on $(REPO_HOST):$(REPO_PORT)...${RESET}"
	@mkdir -p ./pki/certs ./pki/crl
	@./$(BINARY_NAME) repo serve \
		--host $(REPO_HOST) \
		--port $(REPO_PORT) \
		--db-path ./pki/micropki.db \
		--cert-dir ./pki/certs \
		--log-file ./repo.log &
	@echo $$! > $(REPO_PID_FILE)
	@sleep 2
	@echo "${GREEN}✓ Server started with PID $$(cat $(REPO_PID_FILE))${RESET}"

## repo-stop: остановка HTTP сервера
repo-stop:
	@echo "${YELLOW}→ Stopping repository server...${RESET}"
	@if [ -f $(REPO_PID_FILE) ]; then \
		kill -9 $$(cat $(REPO_PID_FILE)) 2>/dev/null || true; \
		rm -f $(REPO_PID_FILE); \
		echo "${GREEN}✓ Server stopped${RESET}"; \
	else \
		pkill -f "micropki-cli repo serve" 2>/dev/null && echo "${GREEN}✓ Server stopped${RESET}" || echo "${YELLOW}No server running${RESET}"; \
	fi

## repo-status: проверка статуса сервера
repo-status:
	@echo "${BOLD}${BLUE}→ Checking repository server status...${RESET}"
	@if pgrep -f "micropki-cli repo serve" >/dev/null; then \
		echo "${GREEN}✓ Server is running${RESET}"; \
		curl -s http://$(REPO_HOST):$(REPO_PORT)/health | jq . 2>/dev/null || curl -s http://$(REPO_HOST):$(REPO_PORT)/health; \
	else \
		echo "${RED}✗ Server is not running${RESET}"; \
	fi

# ============================================================================
# CRL цели (Спринт 4)
# ============================================================================

## crl-revoke: отзыв сертификата по серийному номеру
crl-revoke: build
	@echo "${BOLD}${BLUE}=== Отзыв сертификата ===${RESET}"
	@read -p "Введите серийный номер (hex): " serial; \
	./$(BINARY_NAME) ca revoke $$serial --reason keyCompromise --force --db-path ./pki/micropki.db

## crl-gen: генерация Intermediate CRL
crl-gen: build
	@echo "${BOLD}${BLUE}=== Генерация Intermediate CRL ===${RESET}"
	@./$(BINARY_NAME) ca gen-crl --ca intermediate --next-update $(CRL_NEXT_UPDATE) --db-path ./pki/micropki.db

## crl-check: проверка статуса отзыва сертификата
crl-check: build
	@echo "${BOLD}${BLUE}=== Проверка статуса отзыва ===${RESET}"
	@read -p "Введите серийный номер (hex): " serial; \
	./$(BINARY_NAME) ca check-revoked $$serial --db-path ./pki/micropki.db

## test-crl-unit: модульные тесты CRL
test-crl-unit:
	@echo "${BOLD}${BLUE}→ Running CRL unit tests...${RESET}"
	@go test -v ./micropki/internal/crl -count=1 -cover

# ============================================================================
# OCSP цели (Спринт 5)
# ============================================================================

## test-ocsp: запуск модульных тестов OCSP
test-ocsp:
	@echo "${BOLD}${BLUE}→ Running OCSP unit tests...${RESET}"
	@go test -v ./micropki/internal/ocsp -count=1

## ocsp-serve: запуск OCSP сервера
ocsp-serve:
	@echo "${BOLD}${BLUE}→ Starting OCSP server...${RESET}"
	@mkdir -p ./logs
	@./$(BINARY_NAME) ocsp serve \
		--host 127.0.0.1 \
		--port 8081 \
		--db-path ./pki/micropki.db \
		--responder-cert ./pki/certs/ocsp.cert.pem \
		--responder-key ./pki/certs/ocsp.key.pem \
		--ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
		--cache-ttl 60 \
		--log-file ./ocsp.log

## ocsp-test: тест действительного сертификата
ocsp-test:
	@echo "${BOLD}${BLUE}→ Testing good certificate with OCSP...${RESET}"
	@openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
		-cert ./pki/certs/test1.example.com.cert.pem \
		-url http://127.0.0.1:8081 \
		-resp_text -noverify 2>/dev/null | head -20

# ============================================================================
# Примеры и демонстрации
# ============================================================================

## example-full: создает полную PKI иерархию с БД
example-full: clean-pki build
	@echo "${BOLD}${BLUE}→ Creating full PKI hierarchy with database...${RESET}"
	@mkdir -p ./pki ./pki/crl ./logs
	
	# Root CA
	@echo "${YELLOW}1. Создание корневого CA${RESET}"
	@echo "rootpass123" > ./pki/root-pass.txt
	@./$(BINARY_NAME) ca init \
		--subject "/CN=Test Root CA/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/root-pass.txt \
		--out-dir ./pki/root \
		--validity-days 3650 \
		--force > /dev/null 2>&1
	
	# Intermediate CA
	@echo "${YELLOW}2. Создание промежуточного CA${RESET}"
	@echo "intpass123" > ./pki/int-pass.txt
	@./$(BINARY_NAME) ca issue-intermediate \
		--root-cert ./pki/root/certs/ca.cert.pem \
		--root-key ./pki/root/private/ca.key.pem \
		--root-pass-file ./pki/root-pass.txt \
		--subject "/CN=Test Intermediate CA/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/int-pass.txt \
		--out-dir ./pki/intermediate \
		--db-path ./pki/micropki.db > /dev/null 2>&1
	
	# OCSP responder cert
	@echo "${YELLOW}3. Выпуск OCSP responder сертификата${RESET}"
	@./$(BINARY_NAME) ca issue-ocsp-cert \
		--ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
		--ca-key ./pki/intermediate/private/intermediate.key.pem \
		--ca-pass-file ./pki/int-pass.txt \
		--subject "/CN=OCSP Responder/O=MicroPKI/C=RU" \
		--san dns:localhost \
		--out-dir ./pki/certs > /dev/null 2>&1
	
	# Test certificates
	@echo "${YELLOW}4. Выпуск тестовых сертификатов${RESET}"
	@for i in 1 2; do \
		./$(BINARY_NAME) ca issue-cert \
			--ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
			--ca-key ./pki/intermediate/private/intermediate.key.pem \
			--ca-pass-file ./pki/int-pass.txt \
			--template server \
			--subject "CN=test$$i.example.com" \
			--san dns:test$$i.example.com \
			--out-dir ./pki/certs \
			--db-path ./pki/micropki.db > /dev/null 2>&1; \
	done
	
	@echo "${GREEN}✓ Full PKI hierarchy created in ./pki${RESET}"
	@./$(BINARY_NAME) ca list-certs --db-path ./pki/micropki.db --format table | head -10

## test-all: запуск всех Go-тестов
test-all: build
	@echo "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
	@echo "${BOLD}${MAGENTA}║                  ЗАПУСК ВСЕХ GO-ТЕСТОВ                       ║${RESET}"
	@echo "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
	
	@echo "\n${BOLD}${BLUE}1. Модульные тесты Go:${RESET}"
	@go test ./micropki/internal/... -count=1 -cover | grep -v "no test files" || true
	
	@echo "\n${BOLD}${BLUE}2. Интеграционные тесты:${RESET}"
	@go test ./tests -count=1 -v | grep -v "no test files" || true
	
	@echo "\n${BOLD}${GREEN}✓ Все Go-тесты завершены!${RESET}"
	
## benchmark: запуск бенчмарков
benchmark:
	@echo "${BOLD}${BLUE}→ Running benchmarks...${RESET}"
	@go test -bench=. -benchmem ./...

## deps: показать все зависимости
deps:
	@echo "${BOLD}${BLUE}→ Dependencies:${RESET}"
	@go mod graph

## info: информация о проекте
info:
	@echo "${BOLD}${CYAN}MicroPKI - Спринт 6${RESET}"
	@echo "${YELLOW}Version:${RESET}  $(VERSION)"
	@echo "${YELLOW}Build:${RESET}    $(BUILD_TIME)"
	@echo "${YELLOW}Binary:${RESET}   $(BINARY_NAME)"
	@echo "${YELLOW}Go version:${RESET} $$(go version | cut -d' ' -f3)"
	@echo "${YELLOW}PKI directory:${RESET} ./pki"
	@echo "${YELLOW}Database:${RESET}  ./pki/micropki.db"

## Проверка на неизвестные цели
%:
	@echo "${RED}Неизвестная цель: $@${RESET}"
	@$(MAKE) help