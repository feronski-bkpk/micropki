// Package main реализует интерфейс командной строки для MicroPKI.
// MicroPKI - это минимальная инфраструктура открытых ключей для создания
// и управления корневыми и промежуточными центрами сертификации, выпуска
// и проверки X.509 сертификатов.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"micropki/micropki/internal/ca"
	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/chain"
	"micropki/micropki/internal/cli"
	"micropki/micropki/internal/config"
	"micropki/micropki/internal/crl"
	internalcrypto "micropki/micropki/internal/crypto"
	"micropki/micropki/internal/database"
	"micropki/micropki/internal/ocsp"
	"micropki/micropki/internal/repository"
	"micropki/micropki/internal/serial"
	"micropki/micropki/internal/templates"
)

const (
	// exitCodeSuccess возвращается при успешном выполнении программы.
	exitCodeSuccess = 0
	// exitCodeError возвращается при возникновении ошибки.
	exitCodeError = 1
)

// Config содержит параметры конфигурации для инициализации корневого CA.
// Все поля являются опциональными, если не указано обратное в валидации.
type Config struct {
	// Subject - различающееся имя (DN) в формате /CN=.../O=... или CN=...,O=...
	Subject string
	// KeyType - тип ключа: "rsa" или "ecc"
	KeyType string
	// KeySize - размер ключа: 4096 для RSA, 384 для ECC
	KeySize int
	// PassphraseFile - путь к файлу с парольной фразой для шифрования ключа
	PassphraseFile string
	// OutDir - директория для выходных файлов (по умолчанию ./pki)
	OutDir string
	// ValidityDays - срок действия сертификата в днях (по умолчанию 3650)
	ValidityDays int
	// LogFile - опциональный путь к файлу журнала
	LogFile string
	// Force - принудительная перезапись существующих файлов без подтверждения
	Force bool
}

// main является точкой входа в программу. Она инициализирует логгер,
// обрабатывает аргументы командной строки и запускает соответствующую команду.
// В случае ошибки программа завершается с кодом 1, при успехе - с кодом 0.
func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	if err := run(os.Args[1:], logger); err != nil {
		logger.Printf("ERROR: %v", err)
		os.Exit(exitCodeError)
	}
}

// run обрабатывает аргументы командной строки и вызывает соответствующую
// подкоманду. Возвращает ошибку, если команда не распознана или её выполнение
// завершилось неудачей.
func run(args []string, logger *log.Logger) error {
	if len(args) < 1 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "ca":
		if len(args) < 2 {
			return fmt.Errorf("отсутствует подкоманда для 'ca'\nИспользование: micropki-cli ca <подкоманда> [опции]")
		}
		switch args[1] {
		case "init":
			return runCAInit(args[2:], logger)
		case "issue-intermediate":
			return runCAIssueIntermediate(args[2:], logger)
		case "issue-cert":
			return runCAIssueCert(args[2:], logger)
		case "issue-ocsp-cert":
			return runCAIssueOCSPCert(args[2:], logger)
		case "verify":
			return runCAVerify(args[2:], logger)
		case "verify-chain":
			return runCAVerifyChain(args[2:], logger)
		case "list-certs":
			return runCAListCerts(args[2:], logger)
		case "show-cert":
			return runCAShowCert(args[2:], logger)
		case "revoke":
			return runCARevoke(args[2:], logger)
		case "gen-crl":
			return runCAGenCRL(args[2:], logger)
		case "check-revoked":
			return runCACheckRevoked(args[2:], logger)
		default:
			return fmt.Errorf("неизвестная подкоманда '%s' для 'ca'", args[1])
		}
	case "db":
		if len(args) < 2 {
			return fmt.Errorf("отсутствует подкоманда для 'db'\nИспользование: micropki-cli db <подкоманда> [опции]")
		}
		switch args[1] {
		case "init":
			return runDBInit(args[2:], logger)
		default:
			return fmt.Errorf("неизвестная подкоманда '%s' для 'db'", args[1])
		}
	case "repo":
		if len(args) < 2 {
			return fmt.Errorf("отсутствует подкоманда для 'repo'\nИспользование: micropki-cli repo <подкоманда> [опции]")
		}
		switch args[1] {
		case "serve":
			return runRepoServe(args[2:], logger)
		case "status":
			return runRepoStatus(args[2:], logger)
		default:
			return fmt.Errorf("неизвестная подкоманда '%s' для 'repo'", args[1])
		}
	case "ocsp":
		if len(args) < 2 {
			return fmt.Errorf("отсутствует подкоманда для 'ocsp'\nИспользование: micropki-cli ocsp <подкоманда> [опции]")
		}
		switch args[1] {
		case "serve":
			return runOCSPServe(args[2:], logger)
		default:
			return fmt.Errorf("неизвестная подкоманда '%s' для 'ocsp'", args[1])
		}
	case "client":
		if len(args) < 2 {
			return fmt.Errorf("отсутствует подкоманда для 'client'\nИспользование: micropki-cli client <подкоманда> [опции]")
		}
		return cli.RunClient(args[1:], logger)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("неизвестная команда '%s'", args[0])
	}
}

// printUsage выводит подробную справку по использованию программы,
// включая все доступные команды, подкоманды и их опции.
func printUsage() {
	fmt.Println("MicroPKI - Минимальная инфраструктура открытых ключей")
	fmt.Println("\nИспользование: micropki-cli <команда> [подкоманда] [опции]")

	fmt.Println("\nКоманды CA (центры сертификации):")
	fmt.Println("  ca init                 Инициализация нового корневого CA")
	fmt.Println("  ca issue-intermediate   Создание промежуточного CA, подписанного корневым CA")
	fmt.Println("  ca issue-cert           Выпуск конечного сертификата от промежуточного CA")
	fmt.Println("  ca issue-ocsp-cert      Выпуск сертификата для OCSP-ответчика")
	fmt.Println("  ca verify               Проверка сертификата")
	fmt.Println("  ca verify-chain         Проверка полной цепочки сертификатов")
	fmt.Println("  ca list-certs           Список всех сертификатов в базе данных")
	fmt.Println("  ca show-cert <serial>   Показать сертификат по серийному номеру")
	fmt.Println("  ca revoke <serial>      Отзыв сертификата")
	fmt.Println("  ca gen-crl              Генерация CRL для указанного CA")
	fmt.Println("  ca check-revoked <serial> Проверка статуса отзыва сертификата")

	fmt.Println("\nКоманды Базы данных:")
	fmt.Println("  db init                 Инициализация базы данных SQLite")

	fmt.Println("\nКоманды Репозитория (HTTP сервер):")
	fmt.Println("  repo serve              Запуск HTTP сервера репозитория")
	fmt.Println("  repo status             Проверка статуса сервера репозитория")

	fmt.Println("\nКоманды OCSP (Online Certificate Status Protocol):")
	fmt.Println("  ocsp serve              Запуск OCSP-ответчика")

	fmt.Println("\nКлиентские команды:")
	fmt.Println("  client gen-csr          Генерация закрытого ключа и CSR")
	fmt.Println("  client request-cert     Отправка CSR в УЦ и получение сертификата")
	fmt.Println("  client validate         Проверка цепочки сертификатов")
	fmt.Println("  client check-status     Проверка статуса отзыва сертификата")

	fmt.Println("\nОбщие команды:")
	fmt.Println("  help                    Показать эту справку")

	fmt.Println("\nОпции для CA Init:")
	fmt.Println("  --subject           Различающееся имя (обязательно)")
	fmt.Println("                      Формат: /CN=.../O=... или CN=...,O=...")
	fmt.Println("  --key-type          Тип ключа: rsa или ecc (по умолчанию: rsa)")
	fmt.Println("  --key-size          Размер ключа: 4096 для RSA, 384 для ECC (обязательно)")
	fmt.Println("  --passphrase-file   Путь к файлу с парольной фразой (обязательно)")
	fmt.Println("  --out-dir           Выходная директория (по умолчанию: ./pki)")
	fmt.Println("  --validity-days     Срок действия в днях (по умолчанию: 3650)")
	fmt.Println("  --log-file          Опциональный путь к файлу журнала")
	fmt.Println("  --force             Принудительная перезапись существующих файлов")

	fmt.Println("\nОпции для CA Issue-Intermediate:")
	fmt.Println("  --root-cert         Путь к сертификату корневого CA (PEM) (обязательно)")
	fmt.Println("  --root-key          Путь к зашифрованному закрытому ключу корневого CA (PEM) (обязательно)")
	fmt.Println("  --root-pass-file    Файл с парольной фразой для ключа корневого CA (обязательно)")
	fmt.Println("  --subject           Различающееся имя для промежуточного CA (обязательно)")
	fmt.Println("  --key-type          Тип ключа: rsa или ecc (обязательно)")
	fmt.Println("  --key-size          Размер ключа: 4096 для RSA, 384 для ECC (обязательно)")
	fmt.Println("  --passphrase-file   Парольная фраза для ключа промежуточного CA (обязательно)")
	fmt.Println("  --out-dir           Выходная директория (по умолчанию: ./pki)")
	fmt.Println("  --validity-days     Срок действия (по умолчанию: 1825 ≈ 5 лет)")
	fmt.Println("  --pathlen           Ограничение длины пути (по умолчанию: 0)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (для автоматической вставки)")

	fmt.Println("\nОпции для CA Issue-Cert:")
	fmt.Println("  --ca-cert           Сертификат промежуточного CA (PEM) (обязательно)")
	fmt.Println("  --ca-key            Зашифрованный закрытый ключ промежуточного CA (PEM) (обязательно)")
	fmt.Println("  --ca-pass-file      Парольная фраза для ключа промежуточного CA (обязательно)")
	fmt.Println("  --template          Шаблон сертификата: server, client, code_signing (обязательно)")
	fmt.Println("  --subject           Различающееся имя для сертификата")
	fmt.Println("  --san               Альтернативные имена субъекта (можно указывать несколько раз)")
	fmt.Println("                      Формат: dns:example.com, ip:192.168.1.1, email:user@ex.com, uri:https://ex.com")
	fmt.Println("  --csr               Опционально: подписать внешний CSR вместо генерации нового ключа")
	fmt.Println("  --out-dir           Выходная директория (по умолчанию: ./pki/certs)")
	fmt.Println("  --validity-days     Срок действия конечного сертификата (по умолчанию: 365)")
	fmt.Println("  --key-type          Тип ключа для внутренней генерации: rsa или ecc (по умолчанию: rsa)")
	fmt.Println("  --key-size          Размер ключа для внутренней генерации (по умолчанию: 2048 для RSA, 256 для ECC)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (для автоматической вставки)")

	fmt.Println("\nОпции для CA Issue-OCSP-Cert:")
	fmt.Println("  --ca-cert           Сертификат промежуточного CA (PEM) (обязательно)")
	fmt.Println("  --ca-key            Зашифрованный закрытый ключ CA (PEM) (обязательно)")
	fmt.Println("  --ca-pass-file      Парольная фраза для ключа CA (обязательно)")
	fmt.Println("  --subject           Различающееся имя для OCSP-сертификата (обязательно)")
	fmt.Println("  --san               Альтернативные имена субъекта (dns:... или uri:...)")
	fmt.Println("  --key-type          Тип ключа: rsa или ecc (по умолчанию: rsa)")
	fmt.Println("  --key-size          Размер ключа (RSA: 2048/4096, ECC: 256/384)")
	fmt.Println("  --out-dir           Выходная директория (по умолчанию: ./pki/certs)")
	fmt.Println("  --validity-days     Срок действия в днях (по умолчанию: 365)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (для автоматической вставки)")

	fmt.Println("\nОпции для CA Revoke:")
	fmt.Println("  <serial>            Серийный номер сертификата в hex формате (обязательно)")
	fmt.Println("  --reason            Причина отзыва (по умолчанию: unspecified)")
	fmt.Println("                      Поддерживаемые причины: unspecified, keyCompromise, cACompromise,")
	fmt.Println("                      affiliationChanged, superseded, cessationOfOperation, certificateHold,")
	fmt.Println("                      removeFromCRL, privilegeWithdrawn, aACompromise")
	fmt.Println("  --crl               Путь к CRL файлу для обновления (опционально)")
	fmt.Println("  --force             Пропустить запрос подтверждения")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --out-dir           Выходная директория (для CRL) (по умолчанию: ./pki)")

	fmt.Println("\nОпции для CA Gen-CRL:")
	fmt.Println("  --ca                Имя CA: root или intermediate (или путь к сертификату CA) (обязательно)")
	fmt.Println("  --next-update       Количество дней до следующего обновления (по умолчанию: 7)")
	fmt.Println("  --out-file          Выходной файл для CRL (опционально)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --out-dir           Выходная директория (по умолчанию: ./pki)")

	fmt.Println("\nОпции для CA Check-Revoked:")
	fmt.Println("  <serial>            Серийный номер сертификата в hex формате (обязательно)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")

	fmt.Println("\nОпции для CA List-Certs:")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --status            Фильтр по статусу: valid, revoked, expired")
	fmt.Println("  --format            Формат вывода: table, json, csv (по умолчанию: table)")

	fmt.Println("\nОпции для CA Show-Cert:")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --format            Формат вывода: pem, text (по умолчанию: pem)")

	fmt.Println("\nОпции для DB Init:")
	fmt.Println("  --db-path           Путь к файлу базы данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --force             Принудительная перезапись существующей БД")

	fmt.Println("\nОпции для Repo Serve:")
	fmt.Println("  --host              Адрес для прослушивания (по умолчанию: 127.0.0.1)")
	fmt.Println("  --port              Порт (по умолчанию: 8080)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --cert-dir          Директория с сертификатами CA (по умолчанию: ./pki/certs)")
	fmt.Println("  --log-file          Файл для логов HTTP сервера")
	fmt.Println("  --config            Путь к конфигурационному файлу (YAML/JSON)")
	fmt.Println("  --enable-ocsp       Опционально: включить OCSP-эндпоинт на /ocsp")
	fmt.Println("  --ocsp-port         Порт для OCSP-ответчика (если отдельный процесс)")

	fmt.Println("\nОпции для Repo Status:")
	fmt.Println("  --port              Порт для проверки (по умолчанию: 8080)")

	fmt.Println("\nОпции для OCSP Serve:")
	fmt.Println("  --host              Адрес для прослушивания (по умолчанию: 127.0.0.1)")
	fmt.Println("  --port              Порт (по умолчанию: 8081)")
	fmt.Println("  --db-path           Путь к базе данных SQLite (по умолчанию: ./pki/micropki.db)")
	fmt.Println("  --responder-cert    Путь к сертификату OCSP-ответчика (PEM) (обязательно)")
	fmt.Println("  --responder-key     Путь к ключу OCSP-ответчика (PEM, незашифрованный) (обязательно)")
	fmt.Println("  --ca-cert           Путь к сертификату издателя (PEM) (обязательно)")
	fmt.Println("  --cache-ttl         Время жизни кэша в секундах (по умолчанию: 60)")
	fmt.Println("  --log-file          Файл для логов OCSP сервера")

	fmt.Println("\nОпции для Client Gen-CSR:")
	fmt.Println("  --subject           Различающееся имя (DN) для сертификата (обязательно)")
	fmt.Println("  --key-type          Тип ключа: rsa или ecc (по умолчанию: rsa)")
	fmt.Println("  --key-size          Размер ключа: для RSA 2048/4096, для ECC 256/384 (по умолчанию: 2048/256)")
	fmt.Println("  --san               Альтернативные имена субъекта (можно несколько)")
	fmt.Println("                      Формат: dns:example.com, ip:192.168.1.1, email:user@ex.com")
	fmt.Println("  --out-key           Выходной файл для закрытого ключа (по умолчанию: ./key.pem)")
	fmt.Println("  --out-csr           Выходной файл для CSR (по умолчанию: ./request.csr.pem)")

	fmt.Println("\nОпции для Client Request-Cert:")
	fmt.Println("  --csr               Путь к файлу CSR (PEM) (обязательно)")
	fmt.Println("  --template          Шаблон сертификата: server, client, code_signing (обязательно)")
	fmt.Println("  --ca-url            Базовый URL репозитория (например, http://localhost:8080) (обязательно)")
	fmt.Println("  --out-cert          Выходной файл для сертификата (по умолчанию: ./cert.pem)")
	fmt.Println("  --api-key           API ключ для аутентификации (опционально)")

	fmt.Println("\nОпции для Client Validate:")
	fmt.Println("  --cert              Путь к конечному сертификату (PEM) (обязательно)")
	fmt.Println("  --untrusted         Промежуточные сертификаты (можно несколько)")
	fmt.Println("  --trusted           Путь к доверенному корневому CA (по умолчанию: ./pki/certs/ca.cert.pem)")
	fmt.Println("  --crl               Проверить CRL (локальный файл или URL) (опционально)")
	fmt.Println("  --ocsp              Выполнить OCSP проверку (флаг)")
	fmt.Println("  --mode              Режим: chain (только подпись/срок) или full (включая отзыв) (по умолч: full)")
	fmt.Println("  --format            Формат вывода: text или json (по умолчанию: text)")
	fmt.Println("  --validation-time   Время проверки, по умолчанию сейчас")

	fmt.Println("\nОпции для Client Check-Status:")
	fmt.Println("  --cert              Путь к сертификату (PEM) (обязательно)")
	fmt.Println("  --ca-cert           Сертификат издателя (PEM) (обязательно)")
	fmt.Println("  --crl               Опциональный CRL файл или URL")
	fmt.Println("  --ocsp-url          Переопределить URL OCSP ответчика")
}

// ============================================================================
// Команды для работы с базой данных
// ============================================================================

// runDBInit обрабатывает подкоманду 'db init' для инициализации базы данных.
func runDBInit(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("db-init", flag.ContinueOnError)

	var (
		dbPath string
		force  bool
	)

	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных SQLite")
	cmd.BoolVar(&force, "force", false, "Принудительная перезапись существующей БД")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	logger.Printf("INFO: Инициализация базы данных: %s", dbPath)

	if _, err := os.Stat(dbPath); err == nil && !force {
		logger.Printf("INFO: База данных уже существует. Используйте --force для перезаписи")
		return nil
	}

	dbDir := filepath.Dir(dbPath)
	if dbDir != "." && dbDir != "" {
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			return fmt.Errorf("не удалось создать директорию для БД: %w", err)
		}
	}

	if force {
		os.Remove(dbPath)
	}

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	if err := db.InitSchemaWithCRL(); err != nil {
		return fmt.Errorf("не удалось инициализировать схему БД: %w", err)
	}

	logger.Printf("INFO: База данных успешно инициализирована")
	fmt.Printf("\n✓ База данных инициализирована: %s\n", dbPath)

	return nil
}

// ============================================================================
// Команды CA для работы с БД
// ============================================================================

// runCAListCerts обрабатывает подкоманду 'ca list-certs'.
func runCAListCerts(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("list-certs", flag.ContinueOnError)

	var (
		dbPath string
		status string
		format string
	)

	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных SQLite")
	cmd.StringVar(&status, "status", "", "Фильтр по статусу: valid, revoked, expired")
	cmd.StringVar(&format, "format", "table", "Формат вывода: table, json, csv")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	records, err := db.ListCertificates(status, "")
	if err != nil {
		return fmt.Errorf("не удалось получить список сертификатов: %w", err)
	}

	if len(records) == 0 {
		fmt.Println("Сертификаты не найдены")
		return nil
	}

	switch strings.ToLower(format) {
	case "json":
		return printCertsJSON(records)
	case "csv":
		return printCertsCSV(records)
	case "table":
		printCertsTable(records)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}

	return nil
}

// runCAShowCert обрабатывает подкоманду 'ca show-cert'.
func runCAShowCert(args []string, logger *log.Logger) error {
	if len(args) < 1 {
		return fmt.Errorf("требуется серийный номер\nИспользование: micropki-cli ca show-cert <serial> [опции]")
	}

	serialHex := args[0]

	cmd := flag.NewFlagSet("show-cert", flag.ContinueOnError)

	var (
		dbPath string
		format string
	)

	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных SQLite")
	cmd.StringVar(&format, "format", "pem", "Формат вывода: pem, text")

	if err := cmd.Parse(args[1:]); err != nil {
		return err
	}

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		return fmt.Errorf("сертификат не найден: %w", err)
	}

	switch strings.ToLower(format) {
	case "pem":
		fmt.Print(record.CertPEM)
	case "text":
		printCertText(record)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}

	return nil
}

// runCARevoke обрабатывает подкоманду 'ca revoke' для отзыва сертификата.
func runCARevoke(args []string, logger *log.Logger) error {
	reason := "unspecified"
	crlPath := ""
	force := false
	dbPath := "./pki/micropki.db"
	outDir := "./pki"

	var serialHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--reason":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		case "--crl":
			if i+1 < len(args) {
				crlPath = args[i+1]
				i++
			}
		case "--force":
			force = true
		case "--db-path":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		case "--out-dir":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		default:
			if serialHex == "" && !strings.HasPrefix(args[i], "--") {
				serialHex = args[i]
			}
		}
	}

	if serialHex == "" {
		return fmt.Errorf("требуется серийный номер\nИспользование: micropki-cli ca revoke <serial> [опции]")
	}

	logger.Printf("[revoke] После ручного парсинга:")
	logger.Printf("  serial = %s", serialHex)
	logger.Printf("  --db-path = '%s'", dbPath)
	logger.Printf("  --reason = '%s'", reason)
	logger.Printf("  --force = %v", force)
	logger.Printf("  --out-dir = '%s'", outDir)

	reasonCode, err := crl.ParseReasonCode(reason)
	if err != nil {
		return fmt.Errorf("неподдерживаемая причина отзыва: %w", err)
	}

	logger.Printf("INFO: Отзыв сертификата %s с причиной '%s'", serialHex, reasonCode)

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	revokeMgr := crl.NewRevocationManager(db.DB, filepath.Join(outDir, "crl"))

	revoked, existingReason, err := revokeMgr.CheckRevoked(serialHex)
	if err != nil {
		return fmt.Errorf("ошибка при проверке статуса: %w", err)
	}

	if revoked {
		reasonStr := "неизвестная причина"
		if existingReason != nil {
			reasonStr = existingReason.String()
		}
		logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Сертификат %s уже отозван (причина: %s)", serialHex, reasonStr)
		fmt.Printf("Сертификат %s уже отозван (причина: %s)\n", serialHex, reasonStr)
		return nil
	}

	if !force {
		fmt.Printf("Вы уверены, что хотите отозвать сертификат %s с причиной '%s'? (y/N): ", serialHex, reason)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Операция отменена")
			return nil
		}
	}

	if err := revokeMgr.RevokeCertificate(serialHex, reasonCode); err != nil {
		return fmt.Errorf("не удалось отозвать сертификат: %w", err)
	}

	logger.Printf("INFO: Сертификат %s успешно отозван", serialHex)
	fmt.Printf("\n✓ Сертификат %s отозван с причиной '%s'\n", serialHex, reason)

	if crlPath != "" {
		fmt.Println("Генерация обновлённого CRL...")

		issuer, err := revokeMgr.GetIssuerForCertificate(serialHex)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось определить издателя для автообновления CRL: %v", err)
		} else {
			caName := "intermediate"
			if strings.Contains(issuer, "Root") || strings.Contains(issuer, "root") {
				caName = "root"
			}

			if err := generateCRLForCA(dbPath, outDir, caName, 7, logger); err != nil {
				logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось сгенерировать CRL: %v", err)
			} else {
				fmt.Printf("  CRL обновлён: %s/crl/%s.crl.pem\n", outDir, caName)
			}
		}
	}

	return nil
}

// runCAGenCRL обрабатывает подкоманду 'ca gen-crl' для генерации CRL.
func runCAGenCRL(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("gen-crl", flag.ContinueOnError)

	var (
		caName     string
		nextUpdate int
		outFile    string
		dbPath     string
		outDir     string
	)

	cmd.StringVar(&caName, "ca", "", "Имя CA: root или intermediate (или путь к сертификату CA)")
	cmd.IntVar(&nextUpdate, "next-update", 7, "Количество дней до следующего обновления CRL")
	cmd.StringVar(&outFile, "out-file", "", "Выходной файл для CRL")
	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных")
	cmd.StringVar(&outDir, "out-dir", "./pki", "Выходная директория")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if caName == "" {
		return fmt.Errorf("--ca обязателен (укажите 'root' или 'intermediate')")
	}

	logger.Printf("INFO: Генерация CRL для CA '%s' с nextUpdate через %d дней", caName, nextUpdate)

	if err := generateCRLForCA(dbPath, outDir, caName, nextUpdate, logger); err != nil {
		return fmt.Errorf("не удалось сгенерировать CRL: %w", err)
	}

	return nil
}

// runCACheckRevoked обрабатывает подкоманду 'ca check-revoked' для проверки статуса.
func runCACheckRevoked(args []string, logger *log.Logger) error {
	dbPath := "./pki/micropki.db"
	var serialHex string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db-path":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		default:
			if serialHex == "" && !strings.HasPrefix(args[i], "--") {
				serialHex = args[i]
			}
		}
	}

	if serialHex == "" {
		return fmt.Errorf("требуется серийный номер\nИспользование: micropki-cli ca check-revoked <serial>")
	}

	logger.Printf("[check-revoked] После ручного парсинга:")
	logger.Printf("  serial = %s", serialHex)
	logger.Printf("  --db-path = '%s'", dbPath)

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	revokeMgr := crl.NewRevocationManager(db.DB, "")

	revoked, reason, err := revokeMgr.CheckRevoked(serialHex)
	if err != nil {
		return fmt.Errorf("ошибка при проверке статуса: %w", err)
	}

	if revoked {
		reasonStr := "неизвестная причина"
		if reason != nil {
			reasonStr = reason.String()
		}
		fmt.Printf("Сертификат %s ОТОЗВАН (причина: %s)\n", serialHex, reasonStr)
	} else {
		fmt.Printf("Сертификат %s действителен (не отозван)\n", serialHex)
	}

	return nil
}

// ============================================================================
// Команды для репозитория
// ============================================================================

// runRepoServe обрабатывает подкоманду 'repo serve'.
func runRepoServe(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("repo-serve", flag.ContinueOnError)

	var (
		host       string
		port       int
		dbPath     string
		certDir    string
		logFile    string
		configPath string
	)

	cmd.StringVar(&host, "host", "127.0.0.1", "Адрес для прослушивания")
	cmd.IntVar(&port, "port", 8080, "Порт")
	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных SQLite")
	cmd.StringVar(&certDir, "cert-dir", "./pki/certs", "Директория с сертификатами CA")
	cmd.StringVar(&logFile, "log-file", "", "Файл для логов HTTP сервера")
	cmd.StringVar(&configPath, "config", "", "Путь к конфигурационному файлу")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось загрузить конфигурацию: %v", err)
		} else {
			if host == "127.0.0.1" && cfg.Server.Host != "" {
				host = cfg.Server.Host
			}
			if port == 8080 && cfg.Server.Port != 0 {
				port = cfg.Server.Port
			}
			if dbPath == "./pki/micropki.db" && cfg.Database.Path != "" {
				dbPath = cfg.Database.Path
			}
			if certDir == "./pki/certs" && cfg.Server.CertDir != "" {
				certDir = cfg.Server.CertDir
			}
		}
	}

	serverCfg := &repository.Config{
		Host:    host,
		Port:    port,
		DBPath:  dbPath,
		CertDir: certDir,
		LogFile: logFile,
	}

	server, err := repository.NewServer(serverCfg)
	if err != nil {
		return fmt.Errorf("не удалось создать сервер: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Println("Получен сигнал завершения, останавливаем сервер...")
		if err := server.Stop(); err != nil {
			logger.Printf("Ошибка при остановке сервера: %v", err)
		}
	}()

	logger.Printf("Запуск репозитория на %s:%d", host, port)
	if err := server.Start(host, port); err != nil {
		return fmt.Errorf("ошибка сервера: %w", err)
	}

	return nil
}

// runRepoStatus обрабатывает подкоманду 'repo status'.
func runRepoStatus(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("repo-status", flag.ContinueOnError)

	var port int

	cmd.IntVar(&port, "port", 8080, "Порт для проверки")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err == nil {
		defer resp.Body.Close()
		fmt.Printf("Сервер репозитория запущен на порту %d (статус: %s)\n", port, resp.Status)
		fmt.Printf("Эндпоинты:\n")
		fmt.Printf("  GET http://127.0.0.1:%d/health\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/certificate/<serial>\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/ca/root\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/ca/intermediate\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/crl\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/crl/root.crl\n", port)
		fmt.Printf("  GET http://127.0.0.1:%d/crl/intermediate.crl\n", port)
	} else {
		fmt.Printf("Сервер репозитория не запущен на порту %d\n", port)
	}

	return nil
}

// ============================================================================
// Вспомогательные функции для форматирования вывода
// ============================================================================

// printCertsTable выводит сертификаты в табличном формате.
func printCertsTable(records []*database.CertificateRecord) {
	fmt.Println("\nСертификаты в базе данных:")
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("%-20s %-35s %-20s %-15s %-20s\n", "Серийный номер", "Субъект", "Издатель", "Статус", "Истекает")
	fmt.Println(strings.Repeat("-", 120))

	for _, r := range records {
		serial := r.SerialHex
		if len(serial) > 16 {
			serial = serial[:8] + "..." + serial[len(serial)-8:]
		}

		subject := r.Subject
		if len(subject) > 32 {
			subject = subject[:29] + "..."
		}

		issuer := r.Issuer
		if len(issuer) > 32 {
			issuer = issuer[:29] + "..."
		}

		expires := r.NotAfter.Format("2006-01-02")

		fmt.Printf("%-20s %-35s %-20s %-15s %-20s\n", serial, subject, issuer, r.Status, expires)
	}
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("Всего: %d сертификатов\n", len(records))
}

// printCertsJSON выводит сертификаты в JSON формате.
func printCertsJSON(records []*database.CertificateRecord) error {
	type certInfo struct {
		SerialHex        string `json:"serial_hex"`
		Subject          string `json:"subject"`
		Issuer           string `json:"issuer"`
		NotBefore        string `json:"not_before"`
		NotAfter         string `json:"not_after"`
		Status           string `json:"status"`
		RevocationReason string `json:"revocation_reason,omitempty"`
		RevocationDate   string `json:"revocation_date,omitempty"`
	}

	var infos []certInfo
	for _, r := range records {
		info := certInfo{
			SerialHex: r.SerialHex,
			Subject:   r.Subject,
			Issuer:    r.Issuer,
			NotBefore: r.NotBefore.Format(time.RFC3339),
			NotAfter:  r.NotAfter.Format(time.RFC3339),
			Status:    r.Status,
		}
		if r.RevocationReason.Valid {
			info.RevocationReason = r.RevocationReason.String
		}
		if r.RevocationDate.Valid {
			info.RevocationDate = r.RevocationDate.Time.Format(time.RFC3339)
		}
		infos = append(infos, info)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(infos)
}

// printCertsCSV выводит сертификаты в CSV формате.
func printCertsCSV(records []*database.CertificateRecord) error {
	fmt.Println("serial_hex,subject,issuer,not_before,not_after,status,revocation_reason,revocation_date")
	for _, r := range records {
		reason := ""
		if r.RevocationReason.Valid {
			reason = r.RevocationReason.String
		}
		revDate := ""
		if r.RevocationDate.Valid {
			revDate = r.RevocationDate.Time.Format(time.RFC3339)
		}
		fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			r.SerialHex,
			escapeCSV(r.Subject),
			escapeCSV(r.Issuer),
			r.NotBefore.Format(time.RFC3339),
			r.NotAfter.Format(time.RFC3339),
			r.Status,
			reason,
			revDate,
		)
	}
	return nil
}

// escapeCSV экранирует специальные символы для CSV.
func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		s = strings.ReplaceAll(s, "\"", "\"\"")
		return "\"" + s + "\""
	}
	return s
}

// printCertText выводит информацию о сертификате в читаемом формате.
func printCertText(record *database.CertificateRecord) {
	fmt.Println("\n=== Информация о сертификате ===")
	fmt.Printf("Серийный номер (hex): %s\n", record.SerialHex)
	fmt.Printf("Субъект: %s\n", record.Subject)
	fmt.Printf("Издатель: %s\n", record.Issuer)
	fmt.Printf("Действителен с: %s\n", record.NotBefore.Format(time.RFC3339))
	fmt.Printf("Действителен до: %s\n", record.NotAfter.Format(time.RFC3339))
	fmt.Printf("Статус: %s\n", record.Status)

	if record.RevocationReason.Valid {
		fmt.Printf("Причина отзыва: %s\n", record.RevocationReason.String)
	}
	if record.RevocationDate.Valid {
		fmt.Printf("Дата отзыва: %s\n", record.RevocationDate.Time.Format(time.RFC3339))
	}

	block, _ := pem.Decode([]byte(record.CertPEM))
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			fmt.Printf("\nРасширения X.509:\n")
			fmt.Printf("  Версия: %d\n", cert.Version)
			fmt.Printf("  Алгоритм подписи: %s\n", cert.SignatureAlgorithm)
			fmt.Printf("  Является CA: %v\n", cert.IsCA)
			if len(cert.DNSNames) > 0 {
				fmt.Printf("  DNS имена: %v\n", cert.DNSNames)
			}
			if len(cert.IPAddresses) > 0 {
				fmt.Printf("  IP адреса: %v\n", cert.IPAddresses)
			}
			if len(cert.EmailAddresses) > 0 {
				fmt.Printf("  Email адреса: %v\n", cert.EmailAddresses)
			}
		}
	}
}

// ============================================================================
// Вспомогательные функции для CRL
// ============================================================================

// generateCRLForCA генерирует CRL для указанного CA.
func generateCRLForCA(dbPath, outDir, caName string, nextUpdateDays int, logger *log.Logger) error {
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	var certPath, keyPath, passFile string

	switch caName {
	case "root":
		certPath = filepath.Join(outDir, "root", "certs", "ca.cert.pem")
		keyPath = filepath.Join(outDir, "root", "private", "ca.key.pem")
		passFile = filepath.Join(outDir, "root-pass.txt")
	case "intermediate":
		certPath = filepath.Join(outDir, "intermediate", "certs", "intermediate.cert.pem")
		keyPath = filepath.Join(outDir, "intermediate", "private", "intermediate.key.pem")
		passFile = filepath.Join(outDir, "int-pass.txt")
	default:
		return fmt.Errorf("неизвестное имя CA: %s", caName)
	}

	if _, err := os.Stat(certPath); err != nil {
		logger.Printf("ERROR: Сертификат CA не найден: %v", err)
		return fmt.Errorf("сертификат CA не найден: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		logger.Printf("ERROR: Ключ CA не найден: %v", err)
		return fmt.Errorf("ключ CA не найден: %w", err)
	}

	caCert, err := certs.LoadCertificate(certPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	passphrase, err := readPassphraseFromFile(passFile)
	if err != nil {
		logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось прочитать парольную фразу из %s: %v", passFile, err)
		return fmt.Errorf("не удалось прочитать парольную фразу: %w", err)
	}
	defer internalcrypto.SecureZero(passphrase)

	caKey, err := internalcrypto.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		return fmt.Errorf("не удалось загрузить закрытый ключ CA: %w", err)
	}

	issuerDN := caCert.Subject.String()

	var totalCount int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&totalCount)
	if err != nil {
		logger.Printf("CRL GEN: Ошибка при подсчете всех сертификатов: %v", err)
	}

	var revokedTotal int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").Scan(&revokedTotal)
	if err != nil {
		logger.Printf("CRL GEN: Ошибка при подсчете всех отозванных: %v", err)
	}

	var revokedForIssuer int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked' AND issuer = ?", issuerDN).Scan(&revokedForIssuer)
	if err != nil {
		logger.Printf("CRL GEN: Ошибка при подсчете отозванных для издателя: %v", err)
	}

	revokedRecords, err := db.GetRevokedCertificatesForIssuer(issuerDN)
	if err != nil {
		return fmt.Errorf("не удалось получить отозванные сертификаты: %w", err)
	}

	if len(revokedRecords) == 0 && revokedTotal > 0 {

		allRevoked, err := db.GetRevokedCertificates()
		if err != nil {
		} else {

			for _, rec := range allRevoked {
				if rec.Issuer == issuerDN {
					revokedRecords = append(revokedRecords, rec)
				}
			}
		}
	}

	revokedCerts := make([]crl.RevokedCertificate, 0, len(revokedRecords))
	for _, record := range revokedRecords {

		serialBytes, err := hex.DecodeString(record.SerialHex)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Неверный серийный номер в БД: %s", record.SerialHex)
			continue
		}

		rc := crl.RevokedCertificate{
			SerialNumber:   new(big.Int).SetBytes(serialBytes),
			RevocationTime: record.RevocationDate.Time,
		}

		if record.RevocationReason.Valid && record.RevocationReason.String != "" {
			reason, err := crl.ParseReasonCode(record.RevocationReason.String)
			if err == nil {
				rc.ReasonCode = &reason
			}
		}

		revokedCerts = append(revokedCerts, rc)
	}

	crlStorage := crl.NewCRLStorage(db.DB)
	if err := crlStorage.InitCRLTable(); err != nil {
		return fmt.Errorf("не удалось инициализировать CRL таблицу: %w", err)
	}

	crlNumber, err := crlStorage.GetCRLNumber(issuerDN)
	if err != nil {
		return fmt.Errorf("не удалось получить номер CRL: %w", err)
	}

	newNumber, err := crlStorage.IncrementCRLNumber(issuerDN)
	if err != nil {
		return fmt.Errorf("не удалось увеличить номер CRL: %w", err)
	}

	crlNumber = newNumber

	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.AddDate(0, 0, nextUpdateDays)

	cfg := &crl.CRLConfig{
		IssuerCert:              caCert,
		IssuerKey:               caKey,
		ThisUpdate:              thisUpdate,
		NextUpdate:              nextUpdate,
		RevokedCerts:            revokedCerts,
		CRLNumber:               crlNumber,
		IncludeReasonExtensions: true,
	}

	crlObj, err := crl.GenerateCRL(cfg)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать CRL: %w", err)
	}

	savePath := filepath.Join(outDir, "crl", caName+".crl.pem")

	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err != nil {
		return fmt.Errorf("не удалось создать директорию: %w", err)
	}

	if err := os.WriteFile(savePath, []byte(crlObj.PEM), 0644); err != nil {
		return fmt.Errorf("не удалось сохранить CRL: %w", err)
	}

	if _, err := os.Stat(savePath); err != nil {
		logger.Printf("ERROR: Файл CRL не создан: %v", err)
	}

	info := &crl.CRLInfo{
		CASubject:     issuerDN,
		CRLNumber:     crlNumber,
		LastGenerated: time.Now().UTC(),
		NextUpdate:    nextUpdate,
		ThisUpdate:    thisUpdate,
		CRLPath:       savePath,
		RevokedCount:  len(revokedCerts),
	}

	if err := crlStorage.UpdateCRLInfo(info); err != nil {
		logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось обновить метаданные CRL: %v", err)
	}

	fmt.Printf("\n✓ CRL для CA '%s' сгенерирован:\n", caName)
	fmt.Printf("  Файл: %s\n", savePath)
	fmt.Printf("  Номер CRL: %d\n", crlNumber)
	fmt.Printf("  Отозванных сертификатов в CRL: %d\n", len(revokedCerts))
	fmt.Printf("  Всего отозванных в БД: %d\n", revokedTotal)

	return nil
}

// ============================================================================
// Существующие функции (без изменений)
// ============================================================================

// runCAInit обрабатывает подкоманду 'ca init' для инициализации нового корневого CA.
func runCAInit(args []string, logger *log.Logger) error {
	initCmd := flag.NewFlagSet("init", flag.ContinueOnError)

	var config Config
	initCmd.StringVar(&config.Subject, "subject", "", "Различающееся имя (обязательно)")
	initCmd.StringVar(&config.KeyType, "key-type", "rsa", "Тип ключа: rsa или ecc (по умолчанию: rsa)")
	initCmd.IntVar(&config.KeySize, "key-size", 0, "Размер ключа: 4096 для RSA, 384 для ECC (обязательно)")
	initCmd.StringVar(&config.PassphraseFile, "passphrase-file", "", "Путь к файлу с парольной фразой (обязательно)")
	initCmd.StringVar(&config.OutDir, "out-dir", "./pki", "Выходная директория (по умолчанию: ./pki)")
	initCmd.IntVar(&config.ValidityDays, "validity-days", 3650, "Срок действия в днях (по умолчанию: 3650)")
	initCmd.StringVar(&config.LogFile, "log-file", "", "Опциональный путь к файлу журнала")
	initCmd.BoolVar(&config.Force, "force", false, "Принудительная перезапись без подтверждения")

	initCmd.SetOutput(os.Stderr)

	if err := initCmd.Parse(args); err != nil {
		return fmt.Errorf("не удалось разобрать аргументы: %w", err)
	}

	if config.Subject == "" {
		return fmt.Errorf("--subject обязателен и не может быть пустым")
	}

	config.KeyType = strings.ToLower(config.KeyType)
	if config.KeyType != "rsa" && config.KeyType != "ecc" {
		return fmt.Errorf("--key-type должен быть 'rsa' или 'ecc', получено '%s'", config.KeyType)
	}

	if config.KeySize == 0 {
		return fmt.Errorf("--key-size обязателен")
	}
	switch config.KeyType {
	case "rsa":
		if config.KeySize != 4096 {
			return fmt.Errorf("для RSA --key-size должен быть 4096, получено %d", config.KeySize)
		}
	case "ecc":
		if config.KeySize != 384 {
			return fmt.Errorf("для ECC --key-size должен быть 384, получено %d", config.KeySize)
		}
	}

	if config.PassphraseFile == "" {
		return fmt.Errorf("--passphrase-file обязателен")
	}

	passphrase, err := readPassphraseFromFile(config.PassphraseFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу: %w", err)
	}
	defer internalcrypto.SecureZero(passphrase)

	if config.ValidityDays <= 0 {
		return fmt.Errorf("--validity-days должен быть положительным числом, получено %d", config.ValidityDays)
	}

	if err := setupLogging(logger, config.LogFile); err != nil {
		return fmt.Errorf("не удалось настроить логирование: %w", err)
	}

	logger.Printf("INFO: Запуск инициализации корневого CA")
	logger.Printf("INFO: Субъект: %s", config.Subject)
	logger.Printf("INFO: Тип ключа: %s-%d", config.KeyType, config.KeySize)
	logger.Printf("INFO: Срок действия: %d дней", config.ValidityDays)

	if err := createOutputDirectories(config.OutDir, config.Force, logger); err != nil {
		return fmt.Errorf("не удалось создать выходные директории: %w", err)
	}

	logger.Printf("INFO: Генерация ключевой пары %s...", config.KeyType)
	keyPair, err := internalcrypto.GenerateKeyPair(config.KeyType, config.KeySize)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %w", err)
	}
	logger.Printf("INFO: Ключевая пара успешно сгенерирована")

	logger.Printf("INFO: Создание самоподписанного X.509 сертификата...")

	subject, err := certs.ParseDN(config.Subject)
	if err != nil {
		return fmt.Errorf("не удалось разобрать DN субъекта: %w", err)
	}

	serialGen := serial.NewGenerator(nil)
	serialNum, err := serialGen.GenerateWithEntropy(160)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, config.ValidityDays)

	template := certs.NewRootCATemplate(
		subject, subject, serialNum.Int,
		notBefore, notAfter,
		keyPair.PublicKey,
	)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}
	logger.Printf("INFO: Сертификат успешно создан")

	privateKeyPath := filepath.Join(config.OutDir, "private", "ca.key.pem")
	logger.Printf("INFO: Сохранение зашифрованного закрытого ключа в %s", privateKeyPath)

	if err := internalcrypto.SaveEncryptedPrivateKey(keyPair.PrivateKey, privateKeyPath, passphrase); err != nil {
		return fmt.Errorf("не удалось сохранить закрытый ключ: %w", err)
	}

	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось установить права на файл ключа: %v", err)
	}

	certPath := filepath.Join(config.OutDir, "certs", "ca.cert.pem")
	logger.Printf("INFO: Сохранение сертификата в %s", certPath)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("не удалось сохранить сертификат: %w", err)
	}

	policyPath := filepath.Join(config.OutDir, "policy.txt")
	logger.Printf("INFO: Создание документа политики в %s", policyPath)

	if err := createPolicyDocument(policyPath, config, certDER, serialNum.Int, notBefore, notAfter); err != nil {
		return fmt.Errorf("не удалось создать документ политики: %w", err)
	}

	logger.Printf("INFO: Инициализация корневого CA успешно завершена")
	logger.Printf("INFO: Серийный номер сертификата: %X", serialNum.Int)

	fmt.Printf("\nКорневой CA успешно инициализирован!\n")
	fmt.Printf("Сертификат: %s\n", certPath)
	fmt.Printf("Закрытый ключ: %s (зашифрован)\n", privateKeyPath)
	fmt.Printf("Документ политики: %s\n", policyPath)

	return nil
}

// runCAIssueIntermediate обрабатывает подкоманду 'ca issue-intermediate' для создания
// промежуточного CA, подписанного корневым CA.
func runCAIssueIntermediate(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("issue-intermediate", flag.ContinueOnError)

	var (
		rootCertPath   string
		rootKeyPath    string
		rootPassFile   string
		subject        string
		keyType        string
		keySize        int
		passphraseFile string
		outDir         string
		validityDays   int
		pathLen        int
		dbPath         string
	)

	cmd.StringVar(&rootCertPath, "root-cert", "", "Путь к сертификату корневого CA (PEM)")
	cmd.StringVar(&rootKeyPath, "root-key", "", "Путь к зашифрованному закрытому ключу корневого CA (PEM)")
	cmd.StringVar(&rootPassFile, "root-pass-file", "", "Файл с парольной фразой для ключа корневого CA")
	cmd.StringVar(&subject, "subject", "", "Различающееся имя для промежуточного CA")
	cmd.StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	cmd.IntVar(&keySize, "key-size", 0, "Размер ключа: 4096 для RSA, 384 для ECC")
	cmd.StringVar(&passphraseFile, "passphrase-file", "", "Парольная фраза для ключа промежуточного CA")
	cmd.StringVar(&outDir, "out-dir", "./pki", "Выходная директория")
	cmd.IntVar(&validityDays, "validity-days", 1825, "Срок действия в днях")
	cmd.IntVar(&pathLen, "pathlen", 0, "Ограничение длины пути")
	cmd.StringVar(&dbPath, "db-path", "", "Путь к базе данных SQLite (для автоматической вставки)")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if rootCertPath == "" {
		return fmt.Errorf("--root-cert обязателен")
	}
	if rootKeyPath == "" {
		return fmt.Errorf("--root-key обязателен")
	}
	if rootPassFile == "" {
		return fmt.Errorf("--root-pass-file обязателен")
	}
	if subject == "" {
		return fmt.Errorf("--subject обязателен")
	}
	if keySize == 0 {
		return fmt.Errorf("--key-size обязателен")
	}
	if passphraseFile == "" {
		return fmt.Errorf("--passphrase-file обязателен")
	}

	keyType = strings.ToLower(keyType)
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("--key-type должен быть 'rsa' или 'ecc'")
	}
	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("размер RSA ключа должен быть 4096")
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("размер ECC ключа должен быть 384")
	}

	rootPassphrase, err := readPassphraseFromFile(rootPassFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу корневого CA: %w", err)
	}
	defer internalcrypto.SecureZero(rootPassphrase)

	passphrase, err := readPassphraseFromFile(passphraseFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу: %w", err)
	}
	defer internalcrypto.SecureZero(passphrase)

	parsedSubject, err := certs.ParseDN(subject)
	if err != nil {
		return fmt.Errorf("не удалось разобрать субъект: %w", err)
	}

	if err := setupLogging(logger, ""); err != nil {
		return err
	}

	logger.Printf("INFO: Запуск выпуска промежуточного CA")
	logger.Printf("INFO: Субъект: %s", subject)
	logger.Printf("INFO: Тип ключа: %s-%d", keyType, keySize)
	logger.Printf("INFO: Срок действия: %d дней, PathLen: %d", validityDays, pathLen)

	if err := createOutputDirectories(outDir, true, logger); err != nil {
		return fmt.Errorf("не удалось создать директории: %w", err)
	}

	cfg := &ca.CAConfig{
		RootCertPath:   rootCertPath,
		RootKeyPath:    rootKeyPath,
		RootPassphrase: rootPassphrase,
		Subject:        parsedSubject,
		KeyType:        keyType,
		KeySize:        keySize,
		Passphrase:     passphrase,
		OutDir:         outDir,
		ValidityDays:   validityDays,
		PathLen:        pathLen,
	}

	if err := ca.IssueIntermediate(cfg); err != nil {
		return fmt.Errorf("не удалось выпустить промежуточный CA: %w", err)
	}

	if dbPath != "" {
		certPath := filepath.Join(outDir, "certs", "intermediate.cert.pem")
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось прочитать сертификат для БД: %v", err)
		} else {
			block, _ := pem.Decode(certPEM)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					if err := ca.InsertCertificateIntoDB(dbPath, cert, certPEM, logger); err != nil {
						logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось вставить сертификат в БД: %v", err)
					}
				}
			}
		}
	}

	logger.Printf("INFO: Промежуточный CA успешно выпущен")
	return nil
}

// runCAIssueCert обрабатывает подкоманду 'ca issue-cert' для выпуска конечного
// сертификата от промежуточного CA.
func runCAIssueCert(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("issue-cert", flag.ContinueOnError)

	var (
		caCertPath   string
		caKeyPath    string
		caPassFile   string
		templateType string
		subject      string
		sans         arrayFlags
		csrPath      string
		outDir       string
		validityDays int
		keyType      string
		keySize      int
		dbPath       string
	)

	cmd.StringVar(&caCertPath, "ca-cert", "", "Сертификат промежуточного CA (PEM)")
	cmd.StringVar(&caKeyPath, "ca-key", "", "Зашифрованный закрытый ключ промежуточного CA (PEM)")
	cmd.StringVar(&caPassFile, "ca-pass-file", "", "Парольная фраза для ключа промежуточного CA")
	cmd.StringVar(&templateType, "template", "", "Шаблон сертификата: server, client, code_signing")
	cmd.StringVar(&subject, "subject", "", "Различающееся имя для сертификата")
	cmd.Var(&sans, "san", "Альтернативные имена субъекта (можно указывать несколько раз)")
	cmd.StringVar(&csrPath, "csr", "", "Опционально: подписать внешний CSR вместо генерации нового ключа")
	cmd.StringVar(&outDir, "out-dir", "./pki/certs", "Выходная директория")
	cmd.IntVar(&validityDays, "validity-days", 365, "Срок действия конечного сертификата")
	cmd.StringVar(&keyType, "key-type", "rsa", "Тип ключа для внутренней генерации: rsa или ecc")
	cmd.IntVar(&keySize, "key-size", 0, "Размер ключа для внутренней генерации")
	cmd.StringVar(&dbPath, "db-path", "", "Путь к базе данных SQLite (для автоматической вставки)")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if caCertPath == "" {
		return fmt.Errorf("--ca-cert обязателен")
	}
	if caKeyPath == "" {
		return fmt.Errorf("--ca-key обязателен")
	}
	if caPassFile == "" {
		return fmt.Errorf("--ca-pass-file обязателен")
	}
	if templateType == "" {
		return fmt.Errorf("--template обязателен")
	}

	if csrPath == "" {
		if subject == "" {
			return fmt.Errorf("--subject обязателен при отсутствии --csr")
		}
		if keySize == 0 {
			switch strings.ToLower(keyType) {
			case "rsa":
				keySize = 2048
			case "ecc":
				keySize = 256
			default:
				return fmt.Errorf("--key-type должен быть 'rsa' или 'ecc'")
			}
		}
	}

	var tmplType templates.TemplateType
	switch strings.ToLower(templateType) {
	case "server":
		tmplType = templates.Server
	case "client":
		tmplType = templates.Client
	case "code_signing":
		tmplType = templates.CodeSigning
	default:
		return fmt.Errorf("неверный шаблон: %s (должен быть server, client или code_signing)", templateType)
	}

	caPassphrase, err := readPassphraseFromFile(caPassFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу CA: %w", err)
	}
	defer internalcrypto.SecureZero(caPassphrase)

	var parsedSubject *pkix.Name
	if subject != "" {
		parsedSubject, err = certs.ParseDN(subject)
		if err != nil {
			return fmt.Errorf("не удалось разобрать субъект: %w", err)
		}
	}

	var parsedSANs []templates.SAN
	for _, san := range sans {
		parsed, err := templates.ParseSANString(san)
		if err != nil {
			return fmt.Errorf("неверный SAN '%s': %w", san, err)
		}
		parsedSANs = append(parsedSANs, parsed)
	}

	if err := setupLogging(logger, ""); err != nil {
		return err
	}

	logger.Printf("INFO: Запуск выпуска сертификата")
	logger.Printf("INFO: Шаблон: %s", templateType)
	if subject != "" {
		logger.Printf("INFO: Субъект: %s", subject)
	}
	if len(parsedSANs) > 0 {
		logger.Printf("INFO: SAN: %v", parsedSANs)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("не удалось создать выходную директорию: %w", err)
	}

	cfg := &ca.IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPassphrase,
		Template:     tmplType,
		Subject:      parsedSubject,
		SANs:         parsedSANs,
		CSRPath:      csrPath,
		OutDir:       outDir,
		ValidityDays: validityDays,
		KeyType:      keyType,
		KeySize:      keySize,
	}

	if err := ca.IssueCertificate(cfg); err != nil {
		return fmt.Errorf("не удалось выпустить сертификат: %w", err)
	}

	if dbPath != "" {
		var commonName string
		if parsedSubject != nil && parsedSubject.CommonName != "" {
			commonName = sanitizeFilename(parsedSubject.CommonName)
		} else {
			commonName = fmt.Sprintf("cert-%d", time.Now().Unix())
		}

		certPath := filepath.Join(outDir, commonName+".cert.pem")

		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось прочитать сертификат %s: %v", certPath, err)

			files, err := filepath.Glob(filepath.Join(outDir, "*.cert.pem"))
			if err != nil || len(files) == 0 {
				logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось найти созданный сертификат для БД")
			} else {
				var newest string
				var newestTime time.Time
				for _, f := range files {
					info, err := os.Stat(f)
					if err == nil && (newest == "" || info.ModTime().After(newestTime)) {
						newest = f
						newestTime = info.ModTime()
					}
				}

				if newest != "" {
					certPEM, err = os.ReadFile(newest)
					if err == nil {
						certPath = newest
					}
				}
			}
		}

		if len(certPEM) > 0 {
			block, _ := pem.Decode(certPEM)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					if err := ca.InsertCertificateIntoDB(dbPath, cert, certPEM, logger); err != nil {
						logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось вставить сертификат в БД: %v", err)
					} else {
						logger.Printf("INFO: Сертификат успешно добавлен в БД")
					}
				} else {
					logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось разобрать сертификат: %v", err)
				}
			}
		}
	}

	logger.Printf("INFO: Сертификат успешно выпущен")
	return nil
}

// runCAVerify обрабатывает подкоманду 'ca verify' для проверки одного сертификата.
func runCAVerify(args []string, logger *log.Logger) error {
	verifyCmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	var certPath string
	verifyCmd.StringVar(&certPath, "cert", "", "Путь к файлу сертификата для проверки")

	if err := verifyCmd.Parse(args); err != nil {
		return err
	}

	if certPath == "" {
		return fmt.Errorf("--cert обязателен")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать сертификат: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("не удалось декодировать PEM сертификат")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать сертификат: %w", err)
	}

	if cert.Issuer.String() == cert.Subject.String() {
		if err := certs.VerifySelfSigned(cert); err != nil {
			return fmt.Errorf("ПРОВАЛ проверки сертификата: %w", err)
		}
	} else {
		fmt.Printf("ПРЕДУПРЕЖДЕНИЕ: Сертификат не самоподписанный. Используйте 'ca verify-chain' для проверки полной цепочки.\n")
	}

	fmt.Printf("Проверка сертификата ПРОЙДЕНА\n")
	fmt.Printf("\nДетали сертификата:\n")
	fmt.Printf("  Субъект: %s\n", cert.Subject)
	fmt.Printf("  Издатель: %s\n", cert.Issuer)
	fmt.Printf("  Серийный номер: %X\n", cert.SerialNumber)
	fmt.Printf("  Действителен с: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Действителен до: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Является CA: %v\n", cert.IsCA)

	if cert.IsCA {
		fmt.Printf("  Ограничение длины пути: %d\n", cert.MaxPathLen)
	}

	return nil
}

// runCAVerifyChain обрабатывает подкоманду 'ca verify-chain' для проверки
// полной цепочки сертификатов от конечного до корневого.
func runCAVerifyChain(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("verify-chain", flag.ContinueOnError)

	var (
		leafPath         string
		intermediatePath string
		rootPath         string
	)

	cmd.StringVar(&leafPath, "leaf", "", "Путь к конечному сертификату (PEM)")
	cmd.StringVar(&intermediatePath, "intermediate", "", "Путь к промежуточному сертификату (PEM)")
	cmd.StringVar(&rootPath, "root", "", "Путь к корневому сертификату (PEM)")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if leafPath == "" || intermediatePath == "" || rootPath == "" {
		return fmt.Errorf("--leaf, --intermediate и --root обязательны")
	}

	certChain, err := chain.LoadChain(leafPath, intermediatePath, rootPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить цепочку сертификатов: %w", err)
	}

	fmt.Println(certChain.PrintChainInfo())

	fmt.Println("\nПроверка цепочки...")
	if err := certChain.Verify(); err != nil {
		return fmt.Errorf("ПРОВАЛ проверки цепочки: %w", err)
	}

	if err := certChain.VerifyWithOpenSSLCompatibility(); err != nil {
		fmt.Printf("ПРЕДУПРЕЖДЕНИЕ: %v\n", err)
	}

	fmt.Println("\n✓ Проверка цепочки сертификатов ПРОЙДЕНА")

	fmt.Println("\nДля проверки с OpenSSL:")
	fmt.Printf("  openssl verify -CAfile %s -untrusted %s %s\n",
		rootPath, intermediatePath, leafPath)

	return nil
}

// arrayFlags реализует интерфейс flag.Value для поддержки многократного
// указания одного флага (например, --san dns:example.com --san ip:192.168.1.1).
type arrayFlags []string

// String возвращает строковое представление массива флагов.
func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

// Set добавляет новое значение к массиву флагов.
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// readPassphraseFromFile читает парольную фразу из указанного файла.
func readPassphraseFromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл с парольной фразой: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл с парольной фразой: %w", err)
	}

	passphrase := bytes.TrimRight(content, "\r\n")

	if len(passphrase) == 0 {
		return nil, fmt.Errorf("файл с парольной фразой пуст")
	}

	return passphrase, nil
}

// setupLogging настраивает вывод логгера.
func setupLogging(logger *log.Logger, logFile string) error {
	if logFile == "" {
		return nil
	}

	logDir := filepath.Dir(logFile)
	if logDir != "." && logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("не удалось создать директорию для журнала: %w", err)
		}
	}

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("не удалось открыть файл журнала: %w", err)
	}

	logger.SetOutput(io.MultiWriter(os.Stderr, file))
	return nil
}

// createOutputDirectories создаёт необходимые директории для выходных файлов.
func createOutputDirectories(outDir string, force bool, logger *log.Logger) error {
	privateKeyPath := filepath.Join(outDir, "private", "ca.key.pem")
	certPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	existingFiles := []string{}
	for _, path := range []string{privateKeyPath, certPath, policyPath} {
		if _, err := os.Stat(path); err == nil {
			existingFiles = append(existingFiles, path)
		}
	}

	if len(existingFiles) > 0 && !force {
		fmt.Println("Предупреждение: Следующие файлы уже существуют:")
		for _, f := range existingFiles {
			fmt.Printf("  %s\n", f)
		}
		fmt.Println("Используйте --force для их перезаписи.")
		return fmt.Errorf("файлы будут перезаписаны, операция отменена")
	}

	dirs := []string{
		outDir,
		filepath.Join(outDir, "private"),
		filepath.Join(outDir, "certs"),
		filepath.Join(outDir, "crl"),
	}

	for _, dir := range dirs {
		mode := os.FileMode(0755)
		if strings.HasSuffix(dir, "private") {
			mode = 0700
		}

		if err := os.MkdirAll(dir, mode); err != nil {
			return fmt.Errorf("не удалось создать директорию %s: %w", dir, err)
		}

		if err := os.Chmod(dir, mode); err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось установить права на %s: %v", dir, err)
		}
	}

	return nil
}

// createPolicyDocument создаёт документ политики для корневого CA.
func createPolicyDocument(path string, config Config, certDER []byte,
	serialNumber *big.Int, notBefore, notAfter time.Time) error {

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("не удалось разобрать сертификат для политики: %w", err)
	}

	var policy strings.Builder
	policy.WriteString("ДОКУМЕНТ ПОЛИТИКИ СЕРТИФИКАТОВ MICROPKI\n")
	policy.WriteString(strings.Repeat("=", 40) + "\n\n")

	fmt.Fprintf(&policy, "Версия политики: 1.0\n")
	policy.WriteString(fmt.Sprintf("Дата создания: %s\n", time.Now().UTC().Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("Имя CA (субъект): %s\n", cert.Subject))
	policy.WriteString(fmt.Sprintf("Серийный номер сертификата (hex): %X\n", serialNumber))
	fmt.Fprintf(&policy, "Срок действия:\n")
	policy.WriteString(fmt.Sprintf("  Начало: %s\n", notBefore.Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("  Окончание: %s\n", notAfter.Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("Алгоритм ключа: %s-%d\n", config.KeyType, config.KeySize))
	policy.WriteString(fmt.Sprintf("Алгоритм подписи: %s\n", cert.SignatureAlgorithm))

	policy.WriteString("\nНазначение CA:\n")
	policy.WriteString("  Корневой CA для демонстрационных и образовательных целей MicroPKI.\n")
	policy.WriteString("  Данный CA предназначен для тестирования и изучения PKI.\n")
	policy.WriteString("  НЕ ПРЕДНАЗНАЧЕН ДЛЯ ПРОМЫШЛЕННОГО ИСПОЛЬЗОВАНИЯ.\n")

	policy.WriteString("\nРасширения сертификата:\n")
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			policy.WriteString("  - Основные ограничения: CA=TRUE (критическое)\n")
		}
		if ext.Id.Equal([]int{2, 5, 29, 15}) {
			policy.WriteString("  - Использование ключа: keyCertSign, cRLSign (критическое)\n")
		}
	}

	policy.WriteString("\nМеры безопасности:\n")
	policy.WriteString("  - Закрытый ключ зашифрован с AES-256-GCM\n")
	policy.WriteString("  - Права доступа к файлу ключа: 0600\n")
	policy.WriteString("  - Права доступа к директории ключа: 0700\n")
	policy.WriteString("  - Все операции логируются\n")

	policy.WriteString("\n" + strings.Repeat("-", 40) + "\n")
	policy.WriteString("КОНЕЦ ДОКУМЕНТА ПОЛИТИКИ\n")

	return os.WriteFile(path, []byte(policy.String()), 0644)
}

// sanitizeFilename удаляет символы, небезопасные для имён файлов.
func sanitizeFilename(name string) string {
	result := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// runOCSPServe обрабатывает подкоманду 'ocsp serve'
func runOCSPServe(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("ocsp-serve", flag.ContinueOnError)

	var (
		host          string
		port          int
		dbPath        string
		responderCert string
		responderKey  string
		caCert        string
		cacheTTL      int
		logFile       string
	)

	cmd.StringVar(&host, "host", "127.0.0.1", "Адрес для прослушивания")
	cmd.IntVar(&port, "port", 8081, "Порт")
	cmd.StringVar(&dbPath, "db-path", "./pki/micropki.db", "Путь к базе данных SQLite")
	cmd.StringVar(&responderCert, "responder-cert", "", "Путь к сертификату OCSP-ответчика (PEM)")
	cmd.StringVar(&responderKey, "responder-key", "", "Путь к ключу OCSP-ответчика (PEM, незашифрованный)")
	cmd.StringVar(&caCert, "ca-cert", "", "Путь к сертификату издателя (PEM)")
	cmd.IntVar(&cacheTTL, "cache-ttl", 60, "Время жизни кэша в секундах")
	cmd.StringVar(&logFile, "log-file", "", "Файл для логов OCSP сервера")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if responderCert == "" {
		return fmt.Errorf("--responder-cert обязателен")
	}
	if responderKey == "" {
		return fmt.Errorf("--responder-key обязателен")
	}
	if caCert == "" {
		return fmt.Errorf("--ca-cert обязателен")
	}

	var ocspLogger *log.Logger
	if logFile != "" {
		logDir := filepath.Dir(logFile)
		if logDir != "." && logDir != "" {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return fmt.Errorf("не удалось создать директорию для логов: %w", err)
			}
		}
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("не удалось открыть файл логов: %w", err)
		}
		ocspLogger = log.New(io.MultiWriter(file, os.Stdout), "[OCSP] ", log.LstdFlags)
	} else {
		ocspLogger = log.New(os.Stdout, "[OCSP] ", log.LstdFlags)
	}

	responderCertObj, err := certs.LoadCertificate(responderCert)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат ответчика: %w", err)
	}

	keyPEM, err := os.ReadFile(responderKey)
	if err != nil {
		return fmt.Errorf("не удалось прочитать ключ: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("не удалось декодировать PEM ключа")
	}

	var privateKey interface{}
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("не удалось разобрать ключ: %w", err)
		}
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ключ не поддерживает операцию подписи")
	}

	caCertObj, err := certs.LoadCertificate(caCert)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к БД: %w", err)
	}
	defer db.Close()

	checker := db.NewDatabaseStatusChecker()
	responder := ocsp.NewResponder(&ocsp.ResponderConfig{
		DB:            checker,
		ResponderCert: responderCertObj,
		ResponderKey:  signer,
		IssuerCert:    caCertObj,
		CacheTTL:      cacheTTL,
		Logger:        ocspLogger,
		EnableCache:   true,
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	server := &http.Server{
		Addr:         addr,
		Handler:      responder,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		ocspLogger.Println("Получен сигнал завершения, останавливаем OCSP-ответчик...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			ocspLogger.Printf("Ошибка при остановке сервера: %v", err)
		}
	}()

	ocspLogger.Printf("Запуск OCSP-ответчика на %s", addr)
	ocspLogger.Printf("База данных: %s", dbPath)
	ocspLogger.Printf("Сертификат ответчика: %s", responderCert)
	ocspLogger.Printf("Сертификат издателя: %s", caCert)
	ocspLogger.Printf("Кэш TTL: %d секунд", cacheTTL)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("ошибка сервера: %w", err)
	}

	return nil
}

// runCAIssueOCSPCert обрабатывает подкоманду 'ca issue-ocsp-cert'
func runCAIssueOCSPCert(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("issue-ocsp-cert", flag.ContinueOnError)

	var (
		caCertPath   string
		caKeyPath    string
		caPassFile   string
		subject      string
		sans         arrayFlags
		keyType      string
		keySize      int
		outDir       string
		validityDays int
	)

	cmd.StringVar(&caCertPath, "ca-cert", "", "Сертификат промежуточного CA (PEM)")
	cmd.StringVar(&caKeyPath, "ca-key", "", "Зашифрованный закрытый ключ CA (PEM)")
	cmd.StringVar(&caPassFile, "ca-pass-file", "", "Парольная фраза для ключа CA")
	cmd.StringVar(&subject, "subject", "", "Различающееся имя для OCSP-сертификата")
	cmd.Var(&sans, "san", "Альтернативные имена субъекта (dns:... или uri:...)")
	cmd.StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	cmd.IntVar(&keySize, "key-size", 0, "Размер ключа (RSA: 2048/4096, ECC: 256/384)")
	cmd.StringVar(&outDir, "out-dir", "./pki/certs", "Выходная директория")
	cmd.IntVar(&validityDays, "validity-days", 365, "Срок действия в днях")

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if caCertPath == "" {
		return fmt.Errorf("--ca-cert обязателен")
	}
	if caKeyPath == "" {
		return fmt.Errorf("--ca-key обязателен")
	}
	if caPassFile == "" {
		return fmt.Errorf("--ca-pass-file обязателен")
	}
	if subject == "" {
		return fmt.Errorf("--subject обязателен")
	}
	if keySize == 0 {
		if strings.ToLower(keyType) == "rsa" {
			keySize = 2048
		} else {
			keySize = 256
		}
	}

	keyType = strings.ToLower(keyType)
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("--key-type должен быть 'rsa' или 'ecc'")
	}
	if keyType == "rsa" && (keySize != 2048 && keySize != 4096) {
		return fmt.Errorf("размер RSA ключа должен быть 2048 или 4096")
	}
	if keyType == "ecc" && (keySize != 256 && keySize != 384) {
		return fmt.Errorf("размер ECC ключа должен быть 256 или 384")
	}

	caPassphrase, err := readPassphraseFromFile(caPassFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу CA: %w", err)
	}
	defer internalcrypto.SecureZero(caPassphrase)

	parsedSubject, err := certs.ParseDN(subject)
	if err != nil {
		return fmt.Errorf("не удалось разобрать субъект: %w", err)
	}

	var parsedSANs []templates.SAN
	for _, san := range sans {
		parsed, err := templates.ParseSANString(san)
		if err != nil {
			return fmt.Errorf("неверный SAN '%s': %w", san, err)
		}
		if parsed.Type != "dns" && parsed.Type != "uri" {
			return fmt.Errorf("OCSP сертификат может содержать только DNS или URI SAN")
		}
		parsedSANs = append(parsedSANs, parsed)
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("не удалось создать выходную директорию: %w", err)
	}

	config := &ocsp.SignerConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPassphrase,
		Subject:      parsedSubject,
		SANs:         parsedSANs,
		KeyType:      keyType,
		KeySize:      keySize,
		ValidityDays: validityDays,
		OutDir:       outDir,
	}

	if err := ocsp.IssueOCSPCertificate(config); err != nil {
		return fmt.Errorf("не удалось выпустить OCSP-сертификат: %w", err)
	}

	return nil
}
