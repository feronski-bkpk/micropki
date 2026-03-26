// Package ca реализует операции центра сертификации (Certificate Authority).
// Пакет предоставляет функциональность для создания и управления корневыми
// и промежуточными центрами сертификации, а также для выпуска конечных
// сертификатов.
// Все закрытые ключи хранятся в зашифрованном виде с использованием AES-256-GCM,
// за исключением ключей конечных сертификатов, которые по умолчанию сохраняются
// незашифрованными (с предупреждением).
package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/crypto"
	"micropki/micropki/internal/csr"
	"micropki/micropki/internal/database"
	"micropki/micropki/internal/policy"
	"micropki/micropki/internal/templates"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InsertCertificateIntoDB вставляет сертификат в базу данных.
// Эта функция вызывается из команд выпуска сертификатов.
func InsertCertificateIntoDB(dbPath string, cert *x509.Certificate, certPEM []byte, logger *log.Logger) error {
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось открыть БД: %w", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("не удалось инициализировать схему БД: %w", err)
	}

	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE serial_hex = ?",
		hex.EncodeToString(cert.SerialNumber.Bytes())).Scan(&exists)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
		} else {
			return fmt.Errorf("ошибка при проверке существования сертификата: %w", err)
		}
	}

	if exists > 0 {
		if logger != nil {
			logger.Printf("INFO: Сертификат %X уже существует в БД, пропускаем вставку", cert.SerialNumber)
		}
		return nil
	}

	record := &database.CertificateRecord{
		SerialHex: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		CertPEM:   string(certPEM),
		Status:    "valid",
	}

	if err := db.InsertCertificate(record); err != nil {
		return fmt.Errorf("не удалось вставить сертификат в БД: %w", err)
	}

	if logger != nil {
		logger.Printf("INFO: Сертификат %X добавлен в базу данных", cert.SerialNumber)
	}

	return nil
}

// IssueCertificateFromCSR выпускает сертификат на основе внешнего CSR
func IssueCertificateFromCSR(
	caCertPath, caKeyPath string,
	caPassphrase []byte,
	csrPEM []byte,
	templateType templates.TemplateType,
	validityDays int,
	outDir string,
	dbPath string,
	logger *log.Logger,
) (*x509.Certificate, error) {

	caCert, err := certs.LoadCertificate(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	caKey, err := crypto.LoadEncryptedPrivateKey(caKeyPath, caPassphrase)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить закрытый ключ CA: %w", err)
	}

	parsedCSR, err := csr.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("недействительный CSR: %w", err)
	}

	if csr.IsCARequest(parsedCSR) {
		return nil, fmt.Errorf("CSR запрашивает CA=true - не разрешено для конечных сертификатов")
	}

	sans, err := csr.GetSANsFromCSR(parsedCSR)
	if err != nil {
		return nil, fmt.Errorf("не удалось извлечь SAN из CSR: %w", err)
	}

	if err := csr.ValidateCSRForTemplate(parsedCSR, templateType); err != nil {
		return nil, fmt.Errorf("CSR несовместим с шаблоном: %w", err)
	}

	policyConfig := policy.DefaultPolicyConfig()

	if err := policyConfig.ValidateKeySize(parsedCSR.PublicKey, false, templateType); err != nil {
		return nil, fmt.Errorf("нарушение политики: %w", err)
	}

	if err := policyConfig.ValidateValidity(validityDays, false, false); err != nil {
		return nil, fmt.Errorf("нарушение политики: %w", err)
	}

	if err := policyConfig.ValidateSANs(sans, templateType); err != nil {
		return nil, fmt.Errorf("нарушение политики: %w", err)
	}

	serialNum, err := templates.NewSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	tmplCfg := &templates.TemplateConfig{
		Subject:      &parsedCSR.Subject,
		SANs:         sans,
		SerialNumber: serialNum,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    parsedCSR.PublicKey,
	}

	var template *x509.Certificate
	switch templateType {
	case templates.Server:
		template, err = templates.NewServerTemplate(tmplCfg)
	case templates.Client:
		template, err = templates.NewClientTemplate(tmplCfg)
	case templates.CodeSigning:
		template, err = templates.NewCodeSigningTemplate(tmplCfg)
	default:
		return nil, fmt.Errorf("неподдерживаемый тип шаблона: %s", templateType)
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось создать шаблон: %w", err)
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		parsedCSR.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать сертификат: %w", err)
	}

	newCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать созданный сертификат: %w", err)
	}

	if err := policyConfig.ValidateSignatureAlgorithm(newCert.SignatureAlgorithm); err != nil {
		return nil, fmt.Errorf("нарушение политики: %w", err)
	}

	filename := generateCertFilename(newCert, templateType)
	certPath := filepath.Join(outDir, filename+".cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return nil, fmt.Errorf("не удалось сохранить сертификат: %w", err)
	}

	if dbPath != "" {
		certPEM, err := os.ReadFile(certPath)
		if err == nil {
			if err := InsertCertificateIntoDB(dbPath, newCert, certPEM, logger); err != nil {
				logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось вставить сертификат в БД: %v", err)
			}
		}
	}

	fmt.Printf("\n✓ Сертификат из CSR успешно выпущен!\n")
	fmt.Printf("  Сертификат: %s\n", certPath)
	fmt.Printf("  Серийный номер: %X\n", newCert.SerialNumber)

	return newCert, nil
}
