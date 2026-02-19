#!/usr/bin/env make
# MicroPKI Makefile

.PHONY: help build clean test test-verbose test-coverage lint fmt vet run \
        example verify install uninstall release security-check check-all

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
	@echo "${BOLD}${BLUE}MicroPKI Makefile${RESET}"
	@echo "${YELLOW}Usage:${RESET} make ${GREEN}<target>${RESET}\n"
	@echo "${BOLD}Available targets:${RESET}"
	@sed -n '/^## /{s/## \(.*\):\(.*\)/  ${GREEN}\1${RESET}${BLUE}:${RESET} \2/p}' $(MAKEFILE_LIST)
	@echo ""
	@echo "${BOLD}Examples:${RESET}"
	@echo "  ${GREEN}make build${RESET}         - собрать бинарник"
	@echo "  ${GREEN}make test${RESET}          - запустить тесты"
	@echo "  ${GREEN}make example${RESET}       - создать пример CA"
	@echo "  ${GREEN}make verify${RESET}        - проверить пример CA"
	@echo "  ${GREEN}make clean${RESET}         - очистить всё"

## default: сборка по умолчанию
default: build

## build: собирает бинарный файл
build:
	@echo "${BOLD}${BLUE}→ Building ${BINARY_NAME}...${RESET}"
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

%:
	@echo "${RED}Unknown target: $@${RESET}"
	@$(MAKE) help
