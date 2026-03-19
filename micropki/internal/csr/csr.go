// Package csr реализует операции с запросами на подписание сертификата (CSR)
// в соответствии со стандартом PKCS#10 (RFC 2986).
package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"micropki/micropki/internal/templates"
)

// CSRConfig содержит параметры конфигурации для генерации запроса на подписание сертификата.
type CSRConfig struct {
	Subject    *pkix.Name
	SANs       []templates.SAN
	Key        crypto.PrivateKey
	IsCA       bool
	MaxPathLen int
}

// GenerateIntermediateCSR генерирует CSR для промежуточного центра сертификации.
func GenerateIntermediateCSR(cfg *CSRConfig) ([]byte, error) {
	if cfg.Subject == nil {
		return nil, fmt.Errorf("субъект (subject) обязателен")
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("закрытый ключ (key) обязателен")
	}

	template := &x509.CertificateRequest{
		Subject: *cfg.Subject,
	}

	var dnsNames []string
	var ipAddresses []net.IP

	for _, san := range cfg.SANs {
		switch san.Type {
		case "dns":
			dnsNames = append(dnsNames, san.Value)
		case "ip":
			if ip := net.ParseIP(san.Value); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		case "email":
			template.EmailAddresses = append(template.EmailAddresses, san.Value)
		case "uri":
			if uri, err := url.Parse(san.Value); err == nil {
				template.URIs = append(template.URIs, uri)
			}
		}
	}

	template.DNSNames = dnsNames
	template.IPAddresses = ipAddresses

	if cfg.IsCA {
		var extValue []byte
		if cfg.MaxPathLen >= 0 {
			extValue = []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, byte(cfg.MaxPathLen)}
		} else {
			extValue = []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
		}

		template.Extensions = append(template.Extensions, pkix.Extension{
			Id:       []int{2, 5, 29, 19},
			Critical: true,
			Value:    extValue,
		})
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// ParseAndVerifyCSR парсит PEM-кодированный CSR и проверяет его подпись.
func ParseAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("неверный тип PEM: %s (ожидался CERTIFICATE REQUEST)", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("проверка подписи CSR не пройдена: %w", err)
	}

	return csr, nil
}

// ExtractPublicKey извлекает открытый ключ из CSR.
func ExtractPublicKey(csr *x509.CertificateRequest) (crypto.PublicKey, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR равен nil")
	}
	return csr.PublicKey, nil
}

// IsCARequest проверяет, запрашивает ли CSR права центра сертификации.
func IsCARequest(csr *x509.CertificateRequest) bool {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			return true
		}
	}
	return false
}

// GetSubjectFromCSR возвращает субъект из CSR.
func GetSubjectFromCSR(csr *x509.CertificateRequest) *pkix.Name {
	return &csr.Subject
}

func GetSANsFromCSR(csr *x509.CertificateRequest) ([]templates.SAN, error) {
	var sans []templates.SAN

	for _, dns := range csr.DNSNames {
		sans = append(sans, templates.SAN{Type: "dns", Value: dns})
	}

	for _, ip := range csr.IPAddresses {
		if ip != nil {
			sans = append(sans, templates.SAN{Type: "ip", Value: ip.String()})
		}
	}

	for _, email := range csr.EmailAddresses {
		if email != "" {
			sans = append(sans, templates.SAN{Type: "email", Value: email})
			fmt.Printf("Found Email: %s\n", email)
		}
	}

	for _, uri := range csr.URIs {
		if uri != nil {
			sans = append(sans, templates.SAN{Type: "uri", Value: uri.String()})
			fmt.Printf("Found URI: %s\n", uri.String())
		}
	}

	return sans, nil
}

// ValidateCSRForTemplate проверяет совместимость CSR с заданным шаблоном сертификата.
func ValidateCSRForTemplate(csr *x509.CertificateRequest, tmplType templates.TemplateType) error {
	sans, err := GetSANsFromCSR(csr)
	if err != nil {
		return fmt.Errorf("не удалось извлечь SAN: %w", err)
	}

	switch tmplType {
	case templates.Server:
		hasDNSorIP := false
		for _, san := range sans {
			if san.Type == "dns" || san.Type == "ip" {
				hasDNSorIP = true
				break
			}
		}
		if !hasDNSorIP {
			if csr.Subject.CommonName != "" {
				return nil
			}
			return fmt.Errorf("серверный сертификат требует хотя бы одно DNS или IP имя")
		}

	case templates.CodeSigning:
		if IsCARequest(csr) {
			return fmt.Errorf("сертификат подписи кода не может быть CA")
		}
		for _, san := range sans {
			if san.Type == "ip" || san.Type == "email" {
				return fmt.Errorf("сертификат подписи кода не может содержать IP или email SAN")
			}
		}
	}

	return nil
}
