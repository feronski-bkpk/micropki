// Package certs обрабатывает операции с X.509 сертификатами.
// Предоставляет функции для генерации, парсинга и валидации сертификатов.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// ParseDN парсит строку Distinguished Name в структуру pkix.Name.
// Поддерживает два формата:
//   - Слэш-формат: /CN=.../O=.../C=...
//   - Формат с запятыми: CN=..., O=..., C=...
//
// Возвращает ошибку, если строка пустая или имеет неверный формат.
func ParseDN(dn string) (*pkix.Name, error) {
	name := &pkix.Name{}

	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil, fmt.Errorf("пустая строка DN")
	}

	// Определяем формат по первому символу
	if strings.HasPrefix(dn, "/") {
		return parseSlashFormat(dn, name)
	}
	return parseCommaFormat(dn, name)
}

// parseSlashFormat парсит DN в формате: /CN=.../O=.../C=...
func parseSlashFormat(dn string, name *pkix.Name) (*pkix.Name, error) {
	// Убираем ведущий слэш и разбиваем на части
	parts := strings.Split(dn[1:], "/")

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Разбиваем на ключ=значение
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("неверный компонент DN: %s", part)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		// Заполняем соответствующие поля в зависимости от ключа
		switch key {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		default:
			// Неизвестные атрибуты добавляем как ExtraNames
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 0}, // Общий OID для неизвестных атрибутов
				Value: value,
			})
		}
	}

	return name, nil
}

// parseCommaFormat парсит DN в формате: CN=..., O=..., C=...
func parseCommaFormat(dn string, name *pkix.Name) (*pkix.Name, error) {
	// Разбиваем по запятым
	parts := strings.Split(dn, ",")

	for _, part := range parts {
		// Убираем лишние пробелы и разбиваем на ключ=значение
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("неверный компонент DN: %s", part)
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		// Заполняем поля (для O, OU, C, ST, L может быть несколько значений)
		switch key {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = append(name.Organization, value)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, value)
		case "C":
			name.Country = append(name.Country, value)
		case "ST":
			name.Province = append(name.Province, value)
		case "L":
			name.Locality = append(name.Locality, value)
		default:
			// Неизвестные атрибуты добавляем как ExtraNames
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 0},
				Value: value,
			})
		}
	}

	return name, nil
}

// GenerateSerialNumber генерирует криптографически безопасный серийный номер.
// Требование PKI-2: минимум 20 бит энтропии.
// Реализация: используем 20 байт (160 бит) для надежности.
func GenerateSerialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20) // 160 бит энтропии

	// Используем криптографически безопасный генератор случайных чисел
	_, err := rand.Read(serialBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	// Убеждаемся что число положительное (сбрасываем старший бит)
	serialBytes[0] &= 0x7F

	return new(big.Int).SetBytes(serialBytes), nil
}

// NewRootCATemplate создает шаблон самоподписанного сертификата Root CA.
// Реализует требования PKI-2 и PKI-3:
//   - X.509v3
//   - BasicConstraints: CA=TRUE (критический)
//   - KeyUsage: keyCertSign, cRLSign (критический)
//   - SubjectKeyIdentifier и AuthorityKeyIdentifier
func NewRootCATemplate(subject, issuer *pkix.Name, serialNumber *big.Int,
	notBefore, notAfter time.Time, publicKey crypto.PublicKey) *x509.Certificate {

	return &x509.Certificate{
		// Версия 3 (значение 2 в X.509)
		Version:      2,
		SerialNumber: serialNumber,
		Subject:      *subject,
		Issuer:       *issuer, // Для самоподписанного совпадает с Subject
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		// Публичный ключ
		PublicKey: publicKey,

		// KeyUsage - критическое расширение (PKI-3)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,

		// BasicConstraints - критическое расширение, CA=TRUE (PKI-3)
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1, // Без ограничения длины пути

		// SubjectKeyIdentifier будет сгенерирован автоматически
		// AuthorityKeyIdentifier будет установлен в то же значение для самоподписанного
	}
}

// CertificateMatchesPrivateKey проверяет соответствие сертификата приватному ключу.
// Используется для тестирования (TEST-2).
func CertificateMatchesPrivateKey(cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	// Проверяем соответствие публичного ключа в сертификате и приватного ключа
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		// Для RSA проверяем модуль и публичную экспоненту
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("публичный ключ в сертификате не RSA")
		}
		if priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E {
			return fmt.Errorf("несоответствие RSA ключей")
		}

	case *ecdsa.PrivateKey:
		// Для ECDSA проверяем координаты точки на кривой
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("публичный ключ в сертификате не ECDSA")
		}
		if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
			return fmt.Errorf("несоответствие ECDSA ключей")
		}
		if priv.PublicKey.Curve != pub.Curve {
			return fmt.Errorf("несоответствие кривой ECDSA")
		}

	default:
		return fmt.Errorf("неподдерживаемый тип ключа")
	}

	return nil
}

// GetCertificateInfo возвращает читаемую информацию о сертификате.
// Полезно для отладки и вывода пользователю.
func GetCertificateInfo(cert *x509.Certificate) string {
	var info strings.Builder

	info.WriteString(fmt.Sprintf("Субъект: %s\n", cert.Subject))
	info.WriteString(fmt.Sprintf("Издатель: %s\n", cert.Issuer))
	info.WriteString(fmt.Sprintf("Серийный номер: %X\n", cert.SerialNumber))
	info.WriteString(fmt.Sprintf("Действителен: с %s по %s\n",
		cert.NotBefore.Format("2006-01-02 15:04:05"),
		cert.NotAfter.Format("2006-01-02 15:04:05")))
	info.WriteString(fmt.Sprintf("Алгоритм подписи: %v\n", cert.SignatureAlgorithm))

	// Информация о расширениях
	if cert.IsCA {
		info.WriteString("CA: ДА\n")
	}

	info.WriteString("Назначение ключа: ")
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		info.WriteString("Подпись сертификатов ")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		info.WriteString("Подпись CRL ")
	}
	info.WriteString("\n")

	return info.String()
}

// GetKeyAlgorithm возвращает алгоритм и размер ключа.
// Полезно для policy документа.
func GetKeyAlgorithm(pubKey crypto.PublicKey) (string, int, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen(), nil
	case *ecdsa.PublicKey:
		// Определяем размер ключа по кривой
		switch key.Curve {
		case elliptic.P256():
			return "ECC", 256, nil
		case elliptic.P384():
			return "ECC", 384, nil
		case elliptic.P521():
			return "ECC", 521, nil
		default:
			return "ECC", 0, fmt.Errorf("неизвестная кривая ECC")
		}
	default:
		return "", 0, fmt.Errorf("неподдерживаемый тип ключа: %T", pubKey)
	}
}

// VerifySelfSigned проверяет самоподписанный сертификат.
// Возвращает ошибку если проверка не пройдена.
func VerifySelfSigned(cert *x509.Certificate) error {
	// Для самоподписанного сертификата издатель должен совпадать с субъектом
	if cert.Issuer.String() != cert.Subject.String() {
		return fmt.Errorf("издатель не совпадает с субъектом для самоподписанного сертификата")
	}

	// Проверяем подпись
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("проверка подписи не пройдена: %w", err)
	}

	// Проверяем обязательные расширения для CA
	if !cert.IsCA {
		return fmt.Errorf("сертификат CA должен иметь IsCA=true")
	}

	// Проверяем KeyUsage
	requiredKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("отсутствуют обязательные KeyUsage: keyCertSign и cRLSign")
	}

	return nil
}

// VerifyCertificate проверяет сертификат относительно издателя
func VerifyCertificate(cert *x509.Certificate, issuer *x509.Certificate) error {
	// Проверяем подпись
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("проверка подписи не пройдена: %w", err)
	}

	// Проверяем срок действия
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("сертификат недействителен в текущее время")
	}

	return nil
}

// Добавь в конец файла internal/certs/certs.go:

// LoadCertificate loads and parses a PEM-encoded certificate from file
func LoadCertificate(path string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// SaveCertificate saves a DER-encoded certificate to PEM file
func SaveCertificate(certDER []byte, path string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return os.WriteFile(path, certPEM, 0644)
}
