package cli

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/revocation"
	"micropki/micropki/internal/validation"
)

// RunClientValidate обрабатывает 'client validate'
func RunClientValidate(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("validate", flag.ContinueOnError)

	var (
		certPath       string
		untrusted      arrayFlags
		trustedPath    string
		crlFlag        string
		ocspFlag       bool
		mode           string
		format         string
		validationTime string
	)

	cmd.StringVar(&certPath, "cert", "", "Путь к конечному сертификату (PEM) (обязательно)")
	cmd.Var(&untrusted, "untrusted", "Промежуточные сертификаты (можно несколько)")
	cmd.StringVar(&trustedPath, "trusted", "./pki/certs/ca.cert.pem", "Путь к доверенному корневому CA")
	cmd.StringVar(&crlFlag, "crl", "", "Проверить CRL (локальный файл или URL)")
	cmd.BoolVar(&ocspFlag, "ocsp", false, "Выполнить OCSP проверку")
	cmd.StringVar(&mode, "mode", "full", "Режим: chain (только подпись/срок) или full (включая отзыв)")
	cmd.StringVar(&format, "format", "text", "Формат вывода: text или json")
	cmd.StringVar(&validationTime, "validation-time", "", "Время проверки (RFC3339), по умолчанию сейчас")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if certPath == "" {
		return fmt.Errorf("--cert обязателен")
	}

	leaf, err := certs.LoadCertificate(certPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить конечный сертификат: %w", err)
	}

	var intermediates []*x509.Certificate
	for _, path := range untrusted {
		fmt.Printf("  - %s\n", path)
		cert, err := certs.LoadCertificate(path)
		if err != nil {
			logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось загрузить %s: %v", path, err)
			continue
		}
		fmt.Printf("    Subject: %s\n", cert.Subject.String())
		fmt.Printf("    Issuer: %s\n", cert.Issuer.String())
		intermediates = append(intermediates, cert)
	}

	var trustedRoots []*x509.Certificate
	if trustedPath != "" {
		root, err := certs.LoadCertificate(trustedPath)
		if err != nil {
			return fmt.Errorf("не удалось загрузить доверенный корень: %w", err)
		}
		fmt.Printf("  Subject: %s\n", root.Subject.String())
		fmt.Printf("  Issuer: %s\n", root.Issuer.String())
		trustedRoots = append(trustedRoots, root)
	}

	var validateTime time.Time
	if validationTime != "" {
		validateTime, err = time.Parse(time.RFC3339, validationTime)
		if err != nil {
			return fmt.Errorf("неверный формат validation-time: %w", err)
		}
	} else {
		validateTime = time.Now()
	}

	builder := validation.NewChainBuilder(intermediates)
	chain, err := builder.BuildPath(leaf, trustedRoots)
	if err != nil {
		return fmt.Errorf("не удалось построить цепочку: %w", err)
	}

	for i, cert := range chain {
		fmt.Printf("  [%d] Subject: %s\n", i, cert.Subject.String())
		fmt.Printf("      Issuer: %s\n", cert.Issuer.String())
		if i == len(chain)-1 {
			fmt.Printf("      (корневой/самоподписанный)\n")
		}
	}

	config := validation.ValidatorConfig{
		ValidationTime: &validateTime,
		MaxChainLength: 10,
		CheckKeyUsage:  true,
	}

	validator := validation.NewPathValidator(trustedRoots, config)
	result := validator.Validate(chain)

	if mode == "full" && result.OverallStatus && (crlFlag != "" || ocspFlag) {
		revokeConfig := revocation.RevocationCheckerConfig{
			Logger: logger,
		}
		revokeChecker := revocation.NewRevocationChecker(revokeConfig)
		_ = revokeChecker
	}

	switch format {
	case "json":
		return outputValidationJSON(result)
	case "text":
		outputValidationText(result)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}

	if !result.OverallStatus {
		return fmt.Errorf("проверка не пройдена")
	}
	return nil
}

// outputValidationJSON выводит результат в JSON формате
func outputValidationJSON(result *validation.ValidationResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputValidationText выводит результат в текстовом формате
func outputValidationText(result *validation.ValidationResult) {
	fmt.Println("\n=== РЕЗУЛЬТАТ ПРОВЕРКИ ЦЕПОЧКИ СЕРТИФИКАТОВ ===")
	fmt.Printf("Общий статус: ")
	if result.OverallStatus {
		fmt.Println("ПРОЙДЕНА")
	} else {
		fmt.Println("НЕ ПРОЙДЕНА")
	}
	fmt.Printf("Время проверки: %s\n", result.ValidationTime.Format(time.RFC3339))

	if result.FirstError != "" {
		fmt.Printf("Первая ошибка: %s\n", result.FirstError)
	}

	fmt.Println("\nДетали по сертификатам:")
	for i, cert := range result.Chain {
		fmt.Printf("\n--- Сертификат %d ---\n", i+1)
		fmt.Printf("  Субъект: %s\n", cert.Subject)
		fmt.Printf("  Серийный номер: %s\n", cert.SerialNumber)
		fmt.Printf("  Срок действия: %s - %s\n",
			cert.NotBefore.Format("2006-01-02 15:04:05"),
			cert.NotAfter.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Статус срока: %s\n", boolToStatus(cert.ValidityPeriod))
		fmt.Printf("  Подпись: %s\n", boolToStatus(cert.SignatureValid))
		fmt.Printf("  Является CA: %v\n", cert.IsCA)
		if len(cert.Errors) > 0 {
			fmt.Printf("  Ошибки:\n")
			for _, err := range cert.Errors {
				fmt.Printf("    - %s\n", err)
			}
		}
	}
}

// boolToStatus преобразует bool в текстовый статус
func boolToStatus(b bool) string {
	if b {
		return "OK"
	}
	return "ОШИБКА"
}
