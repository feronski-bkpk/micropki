// Package main реализует интерфейс командной строки для MicroPKI.
// MicroPKI - это минимальная инфраструктура открытых ключей для создания
// и управления корневыми и промежуточными центрами сертификации, выпуска
// и проверки X.509 сертификатов.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/micropki/internal/ca"
	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/chain"
	"micropki/micropki/internal/crypto"
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
		case "verify":
			return runCAVerify(args[2:], logger)
		case "verify-chain":
			return runCAVerifyChain(args[2:], logger)
		default:
			return fmt.Errorf("неизвестная подкоманда '%s' для 'ca'", args[1])
		}
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
	fmt.Println("\nКоманды:")
	fmt.Println("  ca init                 Инициализация нового корневого CA")
	fmt.Println("  ca issue-intermediate   Создание промежуточного CA, подписанного корневым CA")
	fmt.Println("  ca issue-cert           Выпуск конечного сертификата от промежуточного CA")
	fmt.Println("  ca verify               Проверка сертификата")
	fmt.Println("  ca verify-chain         Проверка полной цепочки сертификатов")

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

	fmt.Println("\nОпции для CA Verify:")
	fmt.Println("  --cert              Путь к файлу сертификата для проверки")

	fmt.Println("\nОпции для CA Verify-Chain:")
	fmt.Println("  --leaf              Путь к конечному сертификату (PEM)")
	fmt.Println("  --intermediate      Путь к промежуточному сертификату (PEM)")
	fmt.Println("  --root              Путь к корневому сертификату (PEM)")
}

// runCAInit обрабатывает подкоманду 'ca init' для инициализации нового корневого CA.
// Функция выполняет следующие шаги:
// 1. Парсинг и валидация аргументов командной строки
// 2. Чтение парольной фразы из файла
// 3. Настройка логирования
// 4. Создание выходных директорий
// 5. Генерация ключевой пары
// 6. Создание самоподписанного сертификата
// 7. Сохранение зашифрованного закрытого ключа и сертификата
// 8. Создание документа политики
//
// Возвращает ошибку, если какой-либо из шагов завершился неудачей.
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

	// Валидация обязательных аргументов
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
	defer crypto.SecureZero(passphrase)

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

	// Генерация ключевой пары
	logger.Printf("INFO: Генерация ключевой пары %s...", config.KeyType)
	keyPair, err := crypto.GenerateKeyPair(config.KeyType, config.KeySize)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %w", err)
	}
	logger.Printf("INFO: Ключевая пара успешно сгенерирована")

	// Создание сертификата
	logger.Printf("INFO: Создание самоподписанного X.509 сертификата...")

	subject, err := certs.ParseDN(config.Subject)
	if err != nil {
		return fmt.Errorf("не удалось разобрать DN субъекта: %w", err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, config.ValidityDays)

	template := certs.NewRootCATemplate(
		subject, subject, serialNumber,
		notBefore, notAfter,
		keyPair.PublicKey,
	)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}
	logger.Printf("INFO: Сертификат успешно создан")

	// Сохранение файлов
	privateKeyPath := filepath.Join(config.OutDir, "private", "ca.key.pem")
	logger.Printf("INFO: Сохранение зашифрованного закрытого ключа в %s", privateKeyPath)

	if err := crypto.SaveEncryptedPrivateKey(keyPair.PrivateKey, privateKeyPath, passphrase); err != nil {
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

	if err := createPolicyDocument(policyPath, config, certDER, serialNumber, notBefore, notAfter); err != nil {
		return fmt.Errorf("не удалось создать документ политики: %w", err)
	}

	logger.Printf("INFO: Инициализация корневого CA успешно завершена")
	logger.Printf("INFO: Серийный номер сертификата: %X", serialNumber)

	fmt.Printf("\nКорневой CA успешно инициализирован!\n")
	fmt.Printf("Сертификат: %s\n", certPath)
	fmt.Printf("Закрытый ключ: %s (зашифрован)\n", privateKeyPath)
	fmt.Printf("Документ политики: %s\n", policyPath)

	return nil
}

// runCAIssueIntermediate обрабатывает подкоманду 'ca issue-intermediate' для создания
// промежуточного CA, подписанного корневым CA.
// Функция выполняет валидацию аргументов, загружает корневой CA и создаёт
// новый промежуточный CA с заданными параметрами.
//
// Возвращает ошибку, если какой-либо из шагов завершился неудачей.
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

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Валидация обязательных аргументов
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

	// Валидация типа и размера ключа
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

	// Чтение парольной фразы корневого CA
	rootPassphrase, err := readPassphraseFromFile(rootPassFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу корневого CA: %w", err)
	}
	defer crypto.SecureZero(rootPassphrase)

	// Чтение парольной фразы промежуточного CA
	passphrase, err := readPassphraseFromFile(passphraseFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу: %w", err)
	}
	defer crypto.SecureZero(passphrase)

	// Парсинг DN субъекта
	parsedSubject, err := certs.ParseDN(subject)
	if err != nil {
		return fmt.Errorf("не удалось разобрать субъект: %w", err)
	}

	// Настройка логирования
	if err := setupLogging(logger, ""); err != nil {
		return err
	}

	logger.Printf("INFO: Запуск выпуска промежуточного CA")
	logger.Printf("INFO: Субъект: %s", subject)
	logger.Printf("INFO: Тип ключа: %s-%d", keyType, keySize)
	logger.Printf("INFO: Срок действия: %d дней, PathLen: %d", validityDays, pathLen)

	// Создание выходных директорий
	if err := createOutputDirectories(outDir, true, logger); err != nil {
		return fmt.Errorf("не удалось создать директории: %w", err)
	}

	// Настройка и выпуск промежуточного CA
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

	logger.Printf("INFO: Промежуточный CA успешно выпущен")
	return nil
}

// runCAIssueCert обрабатывает подкоманду 'ca issue-cert' для выпуска конечного
// сертификата от промежуточного CA.
// Функция поддерживает два режима:
// 1. Генерация новой ключевой пары и создание сертификата
// 2. Подписание внешнего CSR
//
// Возвращает ошибку, если какой-либо из шагов завершился неудачей.
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

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	// Валидация обязательных аргументов
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

	// Если нет CSR, требуются subject и размер ключа
	if csrPath == "" {
		if subject == "" {
			return fmt.Errorf("--subject обязателен при отсутствии --csr")
		}
		if keySize == 0 {
			// Установка значений по умолчанию
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

	// Валидация типа шаблона
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

	// Чтение парольной фразы CA
	caPassphrase, err := readPassphraseFromFile(caPassFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать парольную фразу CA: %w", err)
	}
	defer crypto.SecureZero(caPassphrase)

	// Парсинг субъекта, если указан
	var parsedSubject *pkix.Name
	if subject != "" {
		parsedSubject, err = certs.ParseDN(subject)
		if err != nil {
			return fmt.Errorf("не удалось разобрать субъект: %w", err)
		}
	}

	// Парсинг SAN
	var parsedSANs []templates.SAN
	for _, san := range sans {
		parsed, err := templates.ParseSANString(san)
		if err != nil {
			return fmt.Errorf("неверный SAN '%s': %w", san, err)
		}
		parsedSANs = append(parsedSANs, parsed)
	}

	// Настройка логирования
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

	// Создание выходной директории
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("не удалось создать выходную директорию: %w", err)
	}

	// Настройка и выпуск сертификата
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

	logger.Printf("INFO: Сертификат успешно выпущен")
	return nil
}

// runCAVerify обрабатывает подкоманду 'ca verify' для проверки одного сертификата.
// Для самоподписанных сертификатов выполняет полную проверку.
// Для неподписанных сертификатов выводит предупреждение о необходимости проверки цепочки.
//
// Возвращает ошибку, если сертификат не прошел проверку.
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

	// Проверка, самоподписанный ли это сертификат
	if cert.Issuer.String() == cert.Subject.String() {
		// Самоподписанный - проверка через VerifySelfSigned
		if err := certs.VerifySelfSigned(cert); err != nil {
			return fmt.Errorf("ПРОВАЛ проверки сертификата: %w", err)
		}
	} else {
		// Не самоподписанный - нужен издатель
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
// Функция загружает все три сертификата, проверяет их целостность,
// связи между ними и сроки действия.
//
// Возвращает ошибку, если проверка цепочки не удалась.
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

	// Загрузка и проверка цепочки
	certChain, err := chain.LoadChain(leafPath, intermediatePath, rootPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить цепочку сертификатов: %w", err)
	}

	fmt.Println(certChain.PrintChainInfo())

	fmt.Println("\nПроверка цепочки...")
	if err := certChain.Verify(); err != nil {
		return fmt.Errorf("ПРОВАЛ проверки цепочки: %w", err)
	}

	// Дополнительная проверка совместимости с OpenSSL
	if err := certChain.VerifyWithOpenSSLCompatibility(); err != nil {
		fmt.Printf("ПРЕДУПРЕЖДЕНИЕ: %v\n", err)
	}

	fmt.Println("\n✓ Проверка цепочки сертификатов ПРОЙДЕНА")

	// Подсказка для проверки в OpenSSL
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
// Функция удаляет завершающие символы новой строки и проверяет,
// что файл не пустой. Возвращает ошибку, если файл не может быть прочитан
// или пуст.
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
// Если указан путь к файлу журнала, функция создаёт необходимые директории
// и настраивает запись как в stderr, так и в файл.
// Возвращает ошибку, если не удаётся создать директорию или открыть файл.
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
// Проверяет наличие существующих файлов и, если не указан флаг --force,
// предотвращает их перезапись.
// Устанавливает соответствующие права доступа для директорий
// (0700 для private, 0755 для остальных).
//
// Возвращает ошибку, если не удаётся создать директорию или установить права,
// а также если существуют файлы и не указан --force.
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
// Документ включает информацию о сертификате, сроке действия,
// используемых криптографических алгоритмах, расширениях и мерах безопасности.
//
// Возвращает ошибку, если не удаётся разобрать сертификат или записать файл.
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
