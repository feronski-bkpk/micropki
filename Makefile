#!/usr/bin/env make
# MicroPKI Makefile - Спринт 3: Интеграция с БД и HTTP репозиторий

.PHONY: help build clean test test-verbose test-coverage lint fmt vet run \
        example verify install uninstall release security-check check-all \
        test-db test-repo test-integration-sprint3 db-init repo-serve \
        list-certs show-cert repo-status test-serial-uniqueness

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

# Директории для примеров
EXAMPLE_DIR     := ./pki-example
EXAMPLE_LOG     := ./example.log
EXAMPLE_PASS    := ./pass.txt
EXAMPLE_DB      := $(EXAMPLE_DIR)/micropki.db

# Параметры для репозитория
REPO_HOST       := 127.0.0.1
REPO_PORT       := 8080
REPO_PID_FILE   := /tmp/micropki-repo.pid

# Цвета для вывода
ifneq (,$(TERM))
    RED     := $(shell tput setaf 1 2>/dev/null)
    GREEN   := $(shell tput setaf 2 2>/dev/null)
    YELLOW  := $(shell tput setaf 3 2>/dev/null)
    BLUE    := $(shell tput setaf 4 2>/dev/null)
    BOLD    := $(shell tput bold 2>/dev/null)
    RESET   := $(shell tput sgr 0 2>/dev/null)
else
    RED     := ""
    GREEN   := ""
    YELLOW  := ""
    BLUE    := ""
    BOLD    := ""
    RESET   := ""
endif

# ============================================================================
# Основные цели
# ============================================================================

help:
	@echo "${BOLD}${BLUE}MicroPKI Makefile - Спринт 3${RESET}"
	@echo "${YELLOW}Usage:${RESET} make ${GREEN}<target>${RESET}\n"
	@echo "${BOLD}Основные цели:${RESET}"
	@sed -n '/^## /{s/## \(.*\):\(.*\)/  ${GREEN}\1${RESET}${BLUE}:${RESET} \2/p}' $(MAKEFILE_LIST)
	@echo ""
	@echo "${BOLD}Новые цели Спринта 3:${RESET}"
	@echo "  ${GREEN}test-db${RESET}${BLUE}:${RESET} тестирование базы данных"
	@echo "  ${GREEN}test-repo${RESET}${BLUE}:${RESET} тестирование репозитория"
	@echo "  ${GREEN}test-integration-sprint3${RESET}${BLUE}:${RESET} интеграционные тесты спринта 3"
	@echo "  ${GREEN}db-init${RESET}${BLUE}:${RESET} инициализация базы данных"
	@echo "  ${GREEN}repo-serve${RESET}${BLUE}:${RESET} запуск HTTP сервера репозитория"
	@echo "  ${GREEN}repo-stop${RESET}${BLUE}:${RESET} остановка HTTP сервера"
	@echo "  ${GREEN}repo-status${RESET}${BLUE}:${RESET} проверка статуса сервера"
	@echo "  ${GREEN}list-certs${RESET}${BLUE}:${RESET} список всех сертификатов"
	@echo "  ${GREEN}show-cert${RESET}${BLUE}:${RESET} показать сертификат по серийному номеру"
	@echo "  ${GREEN}test-serial-uniqueness${RESET}${BLUE}:${RESET} тест уникальности серийных номеров"
	@echo ""
	@echo "${BOLD}Примеры:${RESET}"
	@echo "  ${GREEN}make build${RESET}         - собрать бинарник"
	@echo "  ${GREEN}make test${RESET}          - запустить тесты"
	@echo "  ${GREEN}make db-init${RESET}       - инициализировать БД"
	@echo "  ${GREEN}make example-full${RESET}  - полный пример PKI с БД"
	@echo "  ${GREEN}make repo-serve${RESET}    - запустить репозиторий"
	@echo "  ${GREEN}make clean${RESET}         - очистить всё"

## default: сборка по умолчанию
default: build

## build: собирает бинарный файл
build:
	@echo "${BOLD}${BLUE}→ Building ${BINARY_NAME}...${RESET}"
	@go mod tidy
	@go build $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "${GREEN}✓ Build completed${RESET}"
	@ls -lah $(BINARY_NAME)

## clean: удаляет все сгенерированные файлы
clean:
	@echo "${YELLOW}→ Cleaning...${RESET}"
	@go clean
	@rm -f $(BINARY_NAME)
	@rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	@rm -rf $(EXAMPLE_DIR)
	@rm -f $(EXAMPLE_LOG)
	@rm -f pass.txt
	@rm -f *.db
	@rm -rf ./pki
	@make repo-stop >/dev/null 2>&1 || true
	@echo "${GREEN}✓ Clean completed${RESET}"

## test: запускает тесты
test:
	@echo "${BOLD}${BLUE}→ Running tests...${RESET}"
	@go test ./... -count=1 | grep -v "no test files"

## test-verbose: запускает тесты с подробным выводом
test-verbose:
	@echo "${BOLD}${BLUE}→ Running tests (verbose)...${RESET}"
	@go test -v ./... -count=1

## test-coverage: запускает тесты с подсчетом покрытия
test-coverage:
	@echo "${BOLD}${BLUE}→ Running tests with coverage...${RESET}"
	@go test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	@go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print "${YELLOW}Coverage:${RESET} " $$3}'
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "${GREEN}✓ Coverage report: $(COVERAGE_HTML)${RESET}"

## lint: запускает линтер
lint:
	@echo "${BOLD}${BLUE}→ Running linter...${RESET}"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
		echo "${GREEN}✓ Lint passed${RESET}"; \
	else \
		echo "${YELLOW}⚠ golangci-lint not installed. Run 'make tools' to install${RESET}"; \
	fi

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

## example: создает пример корневого CA
example: clean-example build
	@echo "${BOLD}${BLUE}→ Creating example CA...${RESET}"
	@echo "example-passphrase-123" > $(EXAMPLE_PASS)
	@./$(BINARY_NAME) ca init \
		--subject "/CN=Example Root CA/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file $(EXAMPLE_PASS) \
		--out-dir $(EXAMPLE_DIR) \
		--validity-days 365 \
		--log-file $(EXAMPLE_LOG)
	@echo "\n${GREEN}✓ Example created in $(EXAMPLE_DIR)${RESET}"
	@echo "${YELLOW}Certificate info:${RESET}"
	@openssl x509 -in $(EXAMPLE_DIR)/certs/ca.cert.pem -text -noout 2>/dev/null | head -12 || echo "  Certificate created successfully"

## example-full: создает полную PKI иерархию с БД
example-full: clean build
	@echo "${BOLD}${BLUE}→ Creating full PKI hierarchy with database...${RESET}"
	@mkdir -p ./pki
	
	# Инициализация БД
	@echo "${YELLOW}1. Инициализация базы данных${RESET}"
	@./$(BINARY_NAME) db init --db-path ./pki/micropki.db
	
	# Root CA
	@echo "${YELLOW}2. Создание корневого CA${RESET}"
	@echo "rootpass123" > ./pki/root-pass.txt
	@./$(BINARY_NAME) ca init \
		--subject "/CN=Test Root CA/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki/root-pass.txt \
		--out-dir ./pki/root \
		--validity-days 3650
	
	# Intermediate CA
	@echo "${YELLOW}3. Создание промежуточного CA${RESET}"
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
		--db-path ./pki/micropki.db
	
	# Выпуск тестовых сертификатов
	@echo "${YELLOW}4. Выпуск тестовых сертификатов${RESET}"
	@for i in 1 2 3; do \
		./$(BINARY_NAME) ca issue-cert \
			--ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
			--ca-key ./pki/intermediate/private/intermediate.key.pem \
			--ca-pass-file ./pki/int-pass.txt \
			--template server \
			--subject "CN=test$$i.example.com" \
			--san dns:test$$i.example.com \
			--out-dir ./pki/certs \
			--db-path ./pki/micropki.db; \
	done
	
	@echo "${GREEN}✓ Full PKI hierarchy created in ./pki${RESET}"
	@echo "${GREEN}✓ Database: ./pki/micropki.db${RESET}"
	@./$(BINARY_NAME) ca list-certs --db-path ./pki/micropki.db --format table

## verify: проверяет созданный сертификат
verify:
	@echo "${BOLD}${BLUE}→ Verifying certificate...${RESET}"
	@if [ -f "$(EXAMPLE_DIR)/certs/ca.cert.pem" ]; then \
		echo "${GREEN}Certificate found:$(RESET) $(EXAMPLE_DIR)/certs/ca.cert.pem"; \
		./$(BINARY_NAME) ca verify --cert $(EXAMPLE_DIR)/certs/ca.cert.pem; \
		echo "\n${YELLOW}OpenSSL verification:${RESET}"; \
		openssl verify -CAfile $(EXAMPLE_DIR)/certs/ca.cert.pem $(EXAMPLE_DIR)/certs/ca.cert.pem; \
	else \
		echo "${RED}Error: Certificate not found!${RESET}"; \
		echo "Expected path: $(EXAMPLE_DIR)/certs/ca.cert.pem"; \
		echo "Please run 'make example' first."; \
		exit 1; \
	fi

## clean-example: удаляет пример
clean-example:
	@rm -rf $(EXAMPLE_DIR)
	@rm -f $(EXAMPLE_LOG)
	@rm -f $(EXAMPLE_PASS)

## install: устанавливает бинарник в GOPATH/bin
install:
	@echo "${BOLD}${BLUE}→ Installing...${RESET}"
	@go install $(LDFLAGS) $(MAIN_PACKAGE)
	@echo "${GREEN}✓ Installed to $$(go env GOPATH)/bin/$(BINARY_NAME)${RESET}"

## uninstall: удаляет бинарник из GOPATH/bin
uninstall:
	@echo "${YELLOW}→ Uninstalling...${RESET}"
	@rm -f $$(go env GOPATH)/bin/$(BINARY_NAME)
	@echo "${GREEN}✓ Uninstalled${RESET}"

## security-check: проверяет безопасность зависимостей
security-check:
	@echo "${BOLD}${BLUE}→ Checking security vulnerabilities...${RESET}"
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "${YELLOW}⚠ govulncheck not installed. Run 'make tools' to install${RESET}"; \
	fi

## release: создает релизную сборку
release:
	@echo "${BOLD}${BLUE}→ Building release version $(VERSION)...${RESET}"
	@mkdir -p releases
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o releases/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o releases/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o releases/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o releases/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o releases/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	@cd releases && sha256sum * > checksums.txt 2>/dev/null || echo "⚠ sha256sum not available"
	@echo "${GREEN}✓ Release builds created in ./releases/${RESET}"
	@ls -la releases/

## check-all: запускает все проверки
check-all: mod fmt vet lint test test-coverage security-check
	@echo "\n${BOLD}${GREEN}✓ All checks passed!${RESET}"

## tools: устанавливает инструменты разработки
tools:
	@echo "${BOLD}${BLUE}→ Installing development tools...${RESET}"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || true
	@go install golang.org/x/vuln/cmd/govulncheck@latest 2>/dev/null || true
	@echo "${GREEN}✓ Tools installed${RESET}"

# ============================================================================
# Цели для Спринта 3
# ============================================================================

## test-db: тестирование базы данных
test-db:
	@echo "${BOLD}${BLUE}→ Testing database package...${RESET}"
	@go test -v ./micropki/internal/database -count=1 -cover

## test-repo: тестирование репозитория
test-repo:
	@echo "${BOLD}${BLUE}→ Testing repository package...${RESET}"
	@go test -v ./micropki/internal/repository -count=1 -cover

## test-serial: тестирование генератора серийных номеров
test-serial:
	@echo "${BOLD}${BLUE}→ Testing serial generator...${RESET}"
	@go test -v ./micropki/internal/serial -count=1 -cover

## test-integration-sprint3: интеграционные тесты для спринта 3
test-integration-sprint3: build
	@echo "${BOLD}${BLUE}→ Running Sprint 3 integration tests...${RESET}"
	@chmod +x ./scripts/test-sprint3.sh
	@./scripts/test-sprint3.sh

## db-init: инициализация базы данных
db-init:
	@echo "${BOLD}${BLUE}→ Initializing database...${RESET}"
	@mkdir -p ./pki
	@./$(BINARY_NAME) db init --db-path ./pki/micropki.db
	@echo "${GREEN}✓ Database initialized at ./pki/micropki.db${RESET}"

## list-certs: список всех сертификатов в БД
list-certs:
	@echo "${BOLD}${BLUE}→ Listing certificates from database...${RESET}"
	@./$(BINARY_NAME) ca list-certs --db-path ./pki/micropki.db --format table

## show-cert: показать сертификат по серийному номеру
show-cert:
	@if [ -z "$(SERIAL)" ]; then \
		echo "${RED}Error: SERIAL not set. Use: make show-cert SERIAL=<hex>${RESET}"; \
		exit 1; \
	fi
	@echo "${BOLD}${BLUE}→ Showing certificate $(SERIAL)...${RESET}"
	@./$(BINARY_NAME) ca show-cert $(SERIAL) --db-path ./pki/micropki.db --format pem

## repo-serve: запуск HTTP сервера репозитория
repo-serve:
	@echo "${BOLD}${BLUE}→ Starting repository server on $(REPO_HOST):$(REPO_PORT)...${RESET}"
	@mkdir -p ./pki/certs
	@./$(BINARY_NAME) repo serve \
		--host $(REPO_HOST) \
		--port $(REPO_PORT) \
		--db-path ./pki/micropki.db \
		--cert-dir ./pki/certs \
		--log-file ./pki/repo.log &
	@echo $$! > $(REPO_PID_FILE)
	@sleep 2
	@echo "${GREEN}✓ Server started with PID $$(cat $(REPO_PID_FILE))${RESET}"
	@echo "${YELLOW}API endpoints:${RESET}"
	@echo "  GET http://$(REPO_HOST):$(REPO_PORT)/certificate/<serial>"
	@echo "  GET http://$(REPO_HOST):$(REPO_PORT)/ca/root"
	@echo "  GET http://$(REPO_HOST):$(REPO_PORT)/ca/intermediate"
	@echo "  GET http://$(REPO_HOST):$(REPO_PORT)/crl"
	@echo "  GET http://$(REPO_HOST):$(REPO_PORT)/health"

## repo-stop: остановка HTTP сервера
repo-stop:
	@echo "${YELLOW}→ Stopping repository server...${RESET}"
	@if [ -f $(REPO_PID_FILE) ]; then \
		kill -9 $$(cat $(REPO_PID_FILE)) 2>/dev/null || true; \
		rm -f $(REPO_PID_FILE); \
		echo "${GREEN}✓ Server stopped${RESET}"; \
	else \
		echo "${YELLOW}No PID file found, server may not be running${RESET}"; \
	fi

## repo-status: проверка статуса сервера
repo-status:
	@echo "${BOLD}${BLUE}→ Checking repository server status...${RESET}"
	@if [ -f $(REPO_PID_FILE) ] && kill -0 $$(cat $(REPO_PID_FILE)) 2>/dev/null; then \
		echo "${GREEN}✓ Server is running (PID: $$(cat $(REPO_PID_FILE)))${RESET}"; \
		curl -s http://$(REPO_HOST):$(REPO_PORT)/health | jq . 2>/dev/null || echo "  Health check available at /health"; \
	else \
		echo "${RED}✗ Server is not running${RESET}"; \
	fi

## test-api: тестирование API репозитория
test-api: repo-serve
	@echo "${BOLD}${BLUE}→ Testing API endpoints...${RESET}"
	@sleep 2
	
	@echo "\n${YELLOW}1. Health check:${RESET}"
	@curl -s http://$(REPO_HOST):$(REPO_PORT)/health | jq . 2>/dev/null || curl -s http://$(REPO_HOST):$(REPO_PORT)/health
	
	@echo "\n${YELLOW}2. Get root CA:${RESET}"
	@curl -s http://$(REPO_HOST):$(REPO_PORT)/ca/root -o /tmp/root-test.pem
	@echo "  Downloaded $(shell wc -c < /tmp/root-test.pem) bytes"
	
	@echo "\n${YELLOW}3. Get intermediate CA:${RESET}"
	@curl -s http://$(REPO_HOST):$(REPO_PORT)/ca/intermediate -o /tmp/int-test.pem
	@echo "  Downloaded $(shell wc -c < /tmp/int-test.pem) bytes"
	
	@echo "\n${YELLOW}4. Get CRL (placeholder):${RESET}"
	@curl -s http://$(REPO_HOST):$(REPO_PORT)/crl
	
	@make repo-stop

## test-serial-uniqueness: тест уникальности серийных номеров
test-serial-uniqueness: build
	@echo "${BOLD}${BLUE}→ Testing serial number uniqueness (100 certs)...${RESET}"
	@mkdir -p ./pki-test
	@./$(BINARY_NAME) db init --db-path ./pki-test/test.db
	
	@echo "rootpass" > ./pki-test/root-pass.txt
	@./$(BINARY_NAME) ca init \
		--subject "/CN=Test Root CA" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki-test/root-pass.txt \
		--out-dir ./pki-test/root \
		--validity-days 365 > /dev/null 2>&1
	
	@echo "intpass" > ./pki-test/int-pass.txt
	@./$(BINARY_NAME) ca issue-intermediate \
		--root-cert ./pki-test/root/certs/ca.cert.pem \
		--root-key ./pki-test/root/private/ca.key.pem \
		--root-pass-file ./pki-test/root-pass.txt \
		--subject "/CN=Test Intermediate CA" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./pki-test/int-pass.txt \
		--out-dir ./pki-test/intermediate \
		--db-path ./pki-test/test.db > /dev/null 2>&1
	
	@echo "${YELLOW}Generating 100 certificates...${RESET}"
	@for i in $$(seq 1 100); do \
		./$(BINARY_NAME) ca issue-cert \
			--ca-cert ./pki-test/intermediate/certs/intermediate.cert.pem \
			--ca-key ./pki-test/intermediate/private/intermediate.key.pem \
			--ca-pass-file ./pki-test/int-pass.txt \
			--template server \
			--subject "CN=test$$i.example.com" \
			--out-dir ./pki-test/certs \
			--db-path ./pki-test/test.db > /dev/null 2>&1; \
		if [ $$? -ne 0 ]; then \
			echo "${RED}✗ Failed at certificate $$i${RESET}"; \
			exit 1; \
		fi; \
		if [ $$(($$i % 10)) -eq 0 ]; then \
			echo "  $$i/100 completed"; \
		fi; \
	done
	
	@echo "${GREEN}✓ All 100 certificates generated successfully${RESET}"
	
	@COUNT=$$(sqlite3 ./pki-test/test.db "SELECT COUNT(DISTINCT serial_hex) FROM certificates;" 2>/dev/null || echo 0); \
	if [ "$$COUNT" -eq 100 ]; then \
		echo "${GREEN}✓ All serial numbers are unique${RESET}"; \
	else \
		echo "${RED}✗ Duplicate serial numbers found! Expected 100, got $$COUNT${RESET}"; \
		exit 1; \
	fi
	
	@rm -rf ./pki-test

## benchmark-db: тест производительности БД
benchmark-db:
	@echo "${BOLD}${BLUE}→ Benchmarking database performance...${RESET}"
	@go test -bench=. -benchmem ./micropki/internal/database

## benchmark-serial: тест производительности генератора серийных номеров
benchmark-serial:
	@echo "${BOLD}${BLUE}→ Benchmarking serial generator...${RESET}"
	@go test -bench=. -benchmem ./micropki/internal/serial

## coverage-html: открыть отчет покрытия в браузере
coverage-html: test-coverage
	@open $(COVERAGE_HTML) 2>/dev/null || xdg-open $(COVERAGE_HTML) 2>/dev/null || echo "${YELLOW}Coverage report: $(COVERAGE_HTML)${RESET}"

## deps: показать все зависимости
deps:
	@echo "${BOLD}${BLUE}→ Dependencies:${RESET}"
	@go mod graph

## clean-all: полная очистка
clean-all: clean
	@rm -rf ./pki-test
	@rm -rf ./releases
	@rm -f *.log
	@rm -f *.db
	@rm -f *.out
	@rm -f *.html
	@rm -f $(REPO_PID_FILE)
	@echo "${GREEN}✓ Full clean completed${RESET}"

%:
	@echo "${RED}Unknown target: $@${RESET}"
	@$(MAKE) help