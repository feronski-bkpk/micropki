// Package csr реализует операции с запросами на подписание сертификата (CSR)
package csr

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	internalcrypto "micropki/micropki/internal/crypto"
	"micropki/micropki/internal/templates"
)

// GenerateConfig содержит параметры для генерации новой ключевой пары и CSR
type GenerateConfig struct {
	Subject    *pkix.Name
	KeyType    string
	KeySize    int
	SANs       []templates.SAN
	OutKeyPath string
	OutCSRPath string
	IsCA       bool
	MaxPathLen int
}

// GenerateKeyAndCSR генерирует новую ключевую пару и CSR
func GenerateKeyAndCSR(cfg *GenerateConfig) (crypto.PrivateKey, error) {
	if cfg.Subject == nil {
		return nil, fmt.Errorf("subject обязателен")
	}

	keyPair, err := internalcrypto.GenerateKeyPair(cfg.KeyType, cfg.KeySize)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать ключ: %w", err)
	}

	csrCfg := &CSRConfig{
		Subject:    cfg.Subject,
		SANs:       cfg.SANs,
		Key:        keyPair.PrivateKey,
		IsCA:       cfg.IsCA,
		MaxPathLen: cfg.MaxPathLen,
	}

	csrPEM, err := GenerateIntermediateCSR(csrCfg)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать CSR: %w", err)
	}

	if cfg.OutKeyPath != "" {
		if err := savePrivateKey(keyPair.PrivateKey, cfg.OutKeyPath); err != nil {
			return nil, fmt.Errorf("не удалось сохранить ключ: %w", err)
		}
	}

	if cfg.OutCSRPath != "" {
		if err := saveCSR(csrPEM, cfg.OutCSRPath); err != nil {
			return nil, fmt.Errorf("не удалось сохранить CSR: %w", err)
		}
	}

	return keyPair.PrivateKey, nil
}

// savePrivateKey сохраняет закрытый ключ в незашифрованном PEM формате
func savePrivateKey(privateKey crypto.PrivateKey, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("не удалось создать директорию: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("не удалось маршалировать ключ: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		return fmt.Errorf("не удалось записать файл: %w", err)
	}

	return nil
}

// saveCSR сохраняет CSR в PEM формате
func saveCSR(csrPEM []byte, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("не удалось создать директорию: %w", err)
	}

	if err := os.WriteFile(path, csrPEM, 0644); err != nil {
		return fmt.Errorf("не удалось записать файл: %w", err)
	}

	return nil
}

// extractSANsFromCSR извлекает SAN из CSR (для обратной совместимости)
func extractSANsFromCSR(csr *x509.CertificateRequest) []templates.SAN {
	var sans []templates.SAN

	for _, dns := range csr.DNSNames {
		sans = append(sans, templates.SAN{Type: "dns", Value: dns})
	}

	for _, ip := range csr.IPAddresses {
		sans = append(sans, templates.SAN{Type: "ip", Value: ip.String()})
	}

	for _, email := range csr.EmailAddresses {
		sans = append(sans, templates.SAN{Type: "email", Value: email})
	}

	for _, uri := range csr.URIs {
		sans = append(sans, templates.SAN{Type: "uri", Value: uri.String()})
	}

	return sans
}
