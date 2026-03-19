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
)

// RunClientCheckStatus обрабатывает 'client check-status'
func RunClientCheckStatus(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("check-status", flag.ContinueOnError)

	var (
		certPath    string
		caCertPath  string
		crlFlag     string
		ocspURLFlag string
		format      string
	)

	cmd.StringVar(&certPath, "cert", "", "Путь к сертификату (PEM) (обязательно)")
	cmd.StringVar(&caCertPath, "ca-cert", "", "Сертификат издателя (PEM) (обязательно)")
	cmd.StringVar(&crlFlag, "crl", "", "Опциональный CRL файл или URL")
	cmd.StringVar(&ocspURLFlag, "ocsp-url", "", "Переопределить URL OCSP ответчика")
	cmd.StringVar(&format, "format", "text", "Формат вывода: text или json")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if certPath == "" {
		return fmt.Errorf("--cert обязателен")
	}
	if caCertPath == "" {
		return fmt.Errorf("--ca-cert обязателен")
	}

	cert, err := certs.LoadCertificate(certPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат: %w", err)
	}

	caCert, err := certs.LoadCertificate(caCertPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	logger.Printf("INFO: Проверка статуса для сертификата %X", cert.SerialNumber)

	config := revocation.RevocationCheckerConfig{
		Logger:          logger,
		OCSPTimeout:     10 * time.Second,
		CRLTimeout:      10 * time.Second,
		AllowExpiredCRL: false,
		MaxCRLSize:      10 * 1024 * 1024,
		CacheTTL:        300,
	}

	checker := revocation.NewRevocationChecker(config)

	result := checker.CheckRevocation(cert, caCert)

	switch format {
	case "json":
		return outputRevocationJSON(result)
	case "text":
		outputRevocationText(result, cert)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}

	return nil
}

// outputRevocationText выводит результат проверки отзыва в текстовом формате
func outputRevocationText(result *revocation.RevocationResult, cert *x509.Certificate) {
	fmt.Println("\n=== СТАТУС ОТЗЫВА СЕРТИФИКАТА ===")
	fmt.Printf("Сертификат: %X\n", cert.SerialNumber)
	fmt.Printf("Субъект: %s\n", cert.Subject.String())
	fmt.Printf("Статус: ")

	switch result.Status {
	case revocation.StatusGood:
		fmt.Println("ДЕЙСТВИТЕЛЕН (не отозван)")
	case revocation.StatusRevoked:
		fmt.Println("ОТОЗВАН")
		if result.RevocationTime != nil {
			fmt.Printf("  Время отзыва: %s\n", result.RevocationTime.Format(time.RFC3339))
		}
		if result.RevocationReason != nil {
			fmt.Printf("  Причина отзыва: %s\n", *result.RevocationReason)
		}
	case revocation.StatusUnknown:
		fmt.Println("НЕИЗВЕСТЕН")
	}

	fmt.Printf("Метод проверки: %s\n", result.Method)

	if result.Error != "" {
		fmt.Printf("Ошибка: %s\n", result.Error)
	}
}

// outputRevocationJSON выводит результат проверки отзыва в JSON формате
func outputRevocationJSON(result *revocation.RevocationResult) error {
	output := struct {
		Status           string     `json:"status"`
		StatusCode       int        `json:"status_code"`
		Method           string     `json:"method"`
		RevocationTime   *time.Time `json:"revocation_time,omitempty"`
		RevocationReason *string    `json:"revocation_reason,omitempty"`
		Error            string     `json:"error,omitempty"`
	}{
		Status:     result.Status.String(),
		StatusCode: int(result.Status),
		Method:     result.Method,
		Error:      result.Error,
	}

	if result.RevocationTime != nil {
		output.RevocationTime = result.RevocationTime
	}
	if result.RevocationReason != nil {
		output.RevocationReason = result.RevocationReason
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
