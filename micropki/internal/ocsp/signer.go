package ocsp

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"micropki/micropki/internal/certs"
	internalcrypto "micropki/micropki/internal/crypto"
	"micropki/micropki/internal/templates"
)

// SignerConfig содержит конфигурацию для создания OCSP-подписанта
type SignerConfig struct {
	// Параметры CA
	CACertPath   string
	CAKeyPath    string
	CAPassphrase []byte

	// Параметры сертификата
	Subject      *pkix.Name
	SANs         []templates.SAN
	KeyType      string
	KeySize      int
	ValidityDays int
	OutDir       string

	// База данных (опционально)
	DBPath string
}

// IssueOCSPCertificate выпускает сертификат OCSP-подписанта
func IssueOCSPCertificate(config *SignerConfig) error {
	caCert, err := certs.LoadCertificate(config.CACertPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	caKey, err := internalcrypto.LoadEncryptedPrivateKey(config.CAKeyPath, config.CAPassphrase)
	if err != nil {
		return fmt.Errorf("не удалось загрузить ключ CA: %w", err)
	}
	defer internalcrypto.SecureZero(config.CAPassphrase)

	keyPair, err := internalcrypto.GenerateKeyPair(config.KeyType, config.KeySize)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать ключевую пару: %w", err)
	}

	serialNum, err := templates.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, config.ValidityDays)

	tmplConfig := &templates.TemplateConfig{
		Subject:      config.Subject,
		SANs:         config.SANs,
		SerialNumber: serialNum,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    keyPair.PublicKey,
	}

	template, err := templates.NewOCSPResponderTemplate(tmplConfig)
	if err != nil {
		return fmt.Errorf("не удалось создать шаблон OCSP-сертификата: %w", err)
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		keyPair.PublicKey,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("не удалось разобрать созданный сертификат: %w", err)
	}

	certPath := filepath.Join(config.OutDir, "ocsp.cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return fmt.Errorf("не удалось сохранить сертификат: %w", err)
	}

	keyPath := filepath.Join(config.OutDir, "ocsp.key.pem")
	if err := internalcrypto.SavePrivateKeyUnencrypted(keyPair.PrivateKey, keyPath); err != nil {
		return fmt.Errorf("не удалось сохранить ключ: %w", err)
	}

	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("не удалось установить права на ключ: %w", err)
	}

	fmt.Printf("\n✓ OCSP responder сертификат успешно выпущен!\n")
	fmt.Printf("  Сертификат: %s\n", certPath)
	fmt.Printf("  Ключ: %s (НЕЗАШИФРОВАННЫЙ, права 0600)\n", keyPath)
	fmt.Printf("  Серийный номер: %X\n", cert.SerialNumber)
	fmt.Printf("  Субъект: %s\n", cert.Subject)
	fmt.Printf("  Действителен до: %s\n", cert.NotAfter.Format("2006-01-02"))

	fmt.Printf("\n  Расширения:\n")
	fmt.Printf("    - Basic Constraints: CA=FALSE\n")
	fmt.Printf("    - Key Usage: digitalSignature\n")
	fmt.Printf("    - Extended Key Usage: OCSPSigning (1.3.6.1.5.5.7.3.9)\n")

	return nil
}
