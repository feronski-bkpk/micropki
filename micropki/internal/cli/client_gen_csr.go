package cli

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/csr"
	"micropki/micropki/internal/templates"
)

// RunClientGenCSR обрабатывает команду 'client gen-csr'
func RunClientGenCSR(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("gen-csr", flag.ContinueOnError)

	var (
		subjectStr string
		keyType    string
		keySize    int
		sans       arrayFlags
		outKey     string
		outCSR     string
	)

	cmd.StringVar(&subjectStr, "subject", "", "Различающееся имя (обязательно)")
	cmd.StringVar(&keyType, "key-type", "rsa", "Тип ключа: rsa или ecc")
	cmd.IntVar(&keySize, "key-size", 0, "Размер ключа (RSA: 2048/4096, ECC: 256/384)")
	cmd.Var(&sans, "san", "Альтернативные имена субъекта (можно несколько)")
	cmd.StringVar(&outKey, "out-key", "./key.pem", "Выходной файл для закрытого ключа")
	cmd.StringVar(&outCSR, "out-csr", "./request.csr.pem", "Выходной файл для CSR")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if subjectStr == "" {
		return fmt.Errorf("--subject обязателен и не может быть пустым")
	}

	keyType = strings.ToLower(keyType)
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("--key-type должен быть 'rsa' или 'ecc', получено '%s'", keyType)
	}

	if keySize == 0 {
		switch keyType {
		case "rsa":
			keySize = 2048
			logger.Printf("INFO: Используется размер ключа RSA-2048 (по умолчанию)")
		case "ecc":
			keySize = 256
			logger.Printf("INFO: Используется размер ключа ECC-P256 (по умолчанию)")
		}
	}

	switch keyType {
	case "rsa":
		if keySize != 2048 && keySize != 4096 {
			return fmt.Errorf("для RSA размер ключа должен быть 2048 или 4096, получено %d", keySize)
		}
	case "ecc":
		if keySize != 256 && keySize != 384 {
			return fmt.Errorf("для ECC размер ключа должен быть 256 или 384, получено %d", keySize)
		}
	}

	subject, err := certs.ParseDN(subjectStr)
	if err != nil {
		return fmt.Errorf("не удалось разобрать subject: %w", err)
	}

	var parsedSANs []templates.SAN
	for _, sanStr := range sans {
		san, err := templates.ParseSANString(sanStr)
		if err != nil {
			return fmt.Errorf("неверный формат SAN '%s': %w", sanStr, err)
		}
		parsedSANs = append(parsedSANs, san)
	}

	logger.Printf("INFO: Генерация CSR")
	logger.Printf("INFO:   Subject: %s", subjectStr)
	logger.Printf("INFO:   Key type: %s-%d", keyType, keySize)
	logger.Printf("INFO:   SAN count: %d", len(parsedSANs))
	logger.Printf("INFO:   Output key: %s", outKey)
	logger.Printf("INFO:   Output CSR: %s", outCSR)

	for _, path := range []string{outKey, outCSR} {
		dir := filepath.Dir(path)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("не удалось создать директорию %s: %w", dir, err)
			}
		}
	}

	cfg := &csr.GenerateConfig{
		Subject:    subject,
		KeyType:    keyType,
		KeySize:    keySize,
		SANs:       parsedSANs,
		OutKeyPath: outKey,
		OutCSRPath: outCSR,
		IsCA:       false,
	}

	_, err = csr.GenerateKeyAndCSR(cfg)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать CSR: %w", err)
	}

	fmt.Printf("\nCSR успешно создан!\n")
	fmt.Printf("   Закрытый ключ: %s\n", outKey)
	fmt.Printf("   CSR: %s\n", outCSR)
	fmt.Printf("\nПРЕДУПРЕЖДЕНИЕ: Закрытый ключ сохранён БЕЗ ШИФРОВАНИЯ\n")
	fmt.Printf("   Права доступа: 0600 (только для владельца)\n")

	return nil
}
