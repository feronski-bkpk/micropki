package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RunClientRequestCert обрабатывает команду 'client request-cert'
func RunClientRequestCert(args []string, logger *log.Logger) error {
	cmd := flag.NewFlagSet("request-cert", flag.ContinueOnError)

	var (
		csrPath  string
		template string
		caURL    string
		outCert  string
		apiKey   string
		timeout  int
	)

	cmd.StringVar(&csrPath, "csr", "", "Путь к файлу CSR (PEM) (обязательно)")
	cmd.StringVar(&template, "template", "", "Шаблон сертификата: server, client, code_signing (обязательно)")
	cmd.StringVar(&caURL, "ca-url", "", "Базовый URL репозитория (обязательно)")
	cmd.StringVar(&outCert, "out-cert", "./cert.pem", "Выходной файл для сертификата")
	cmd.StringVar(&apiKey, "api-key", "", "API ключ для аутентификации (опционально)")
	cmd.IntVar(&timeout, "timeout", 30, "Таймаут HTTP запроса в секундах")

	cmd.SetOutput(os.Stderr)

	if err := cmd.Parse(args); err != nil {
		return err
	}

	if csrPath == "" {
		return fmt.Errorf("--csr обязателен")
	}
	if template == "" {
		return fmt.Errorf("--template обязателен")
	}
	if caURL == "" {
		return fmt.Errorf("--ca-url обязателен")
	}

	switch template {
	case "server", "client", "code_signing":

	default:
		return fmt.Errorf("--template должен быть server, client или code_signing")
	}

	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать CSR: %w", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return fmt.Errorf("файл не является действительным CSR (ожидается PEM с типом CERTIFICATE REQUEST)")
	}

	reqURL := fmt.Sprintf("%s/request-cert?template=%s", strings.TrimRight(caURL, "/"), template)
	logger.Printf("INFO: Отправка CSR в %s", reqURL)

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(csrPEM))
	if err != nil {
		return fmt.Errorf("не удалось создать запрос: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("User-Agent", "MicroPKI-Client/1.0")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("не удалось отправить запрос: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("не удалось прочитать ответ: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул ошибку %d: %s", resp.StatusCode, string(body))
	}

	block, _ = pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("сервер вернул некорректный ответ (ожидался PEM сертификат)")
	}

	if err := os.MkdirAll(filepath.Dir(outCert), 0755); err != nil {
		return fmt.Errorf("не удалось создать директорию: %w", err)
	}

	if err := os.WriteFile(outCert, body, 0644); err != nil {
		return fmt.Errorf("не удалось сохранить сертификат: %w", err)
	}

	fmt.Printf("\nСертификат успешно получен!\n")
	fmt.Printf("   Сертификат: %s\n", outCert)
	fmt.Printf("   URL: %s\n", reqURL)
	fmt.Printf("   Шаблон: %s\n", template)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		fmt.Printf("   Серийный номер: %X\n", cert.SerialNumber)
		fmt.Printf("   Действителен до: %s\n", cert.NotAfter.Format("2006-01-02"))
	}

	return nil
}
