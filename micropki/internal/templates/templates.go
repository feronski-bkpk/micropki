// Package templates реализует шаблоны X.509 сертификатов для различных сценариев использования.
// Поддерживает серверные, клиентские сертификаты и сертификаты подписи кода с правильными
// расширениями в соответствии с RFC 5280.
//
// Каждый шаблон включает соответствующие расширения:
//   - Basic Constraints (критическое)
//   - Key Usage (критическое)
//   - Extended Key Usage
//   - Subject Alternative Name
//
// Пакет также предоставляет функции для создания шаблонов промежуточных центров сертификации.
package templates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// TemplateType определяет тип шаблона сертификата.
// Используется для выбора соответствующей конфигурации расширений.
type TemplateType string

const (
	// Server - шаблон для серверных TLS сертификатов
	Server TemplateType = "server"

	// Client - шаблон для клиентских TLS сертификатов
	Client TemplateType = "client"

	// CodeSigning - шаблон для сертификатов подписи кода
	CodeSigning TemplateType = "code_signing"
)

// SAN представляет запись альтернативного имени субъекта.
// Используется для передачи SAN между компонентами системы.
type SAN struct {
	// Type - тип SAN: "dns", "ip", "email", "uri"
	Type string

	// Value - значение SAN в строковом формате
	Value string
}

// TemplateConfig содержит параметры конфигурации для создания шаблонов сертификатов.
// Все поля должны быть заполнены перед вызовом функций создания шаблонов.
type TemplateConfig struct {
	// Subject - различающееся имя субъекта
	Subject *pkix.Name

	// SANs - альтернативные имена субъекта
	SANs []SAN

	// SerialNumber - серийный номер сертификата
	SerialNumber *SerialNumber

	// NotBefore - начало периода действия
	NotBefore time.Time

	// NotAfter - окончание периода действия
	NotAfter time.Time

	// PublicKey - открытый ключ сертификата
	PublicKey interface{}

	// IsCA - флаг центра сертификации (для CA сертификатов)
	IsCA bool

	// MaxPathLen - ограничение длины пути (для CA сертификатов)
	MaxPathLen int

	// KeyUsage - использование ключа (опционально, для переопределения)
	KeyUsage x509.KeyUsage

	// ExtKeyUsage - расширенное использование ключа (опционально)
	ExtKeyUsage []x509.ExtKeyUsage
}

// NewServerTemplate создаёт шаблон для сертификатов аутентификации сервера.
// Реализует требования PKI-8 для серверных сертификатов:
//   - Basic Constraints: CA=FALSE (критическое)
//   - Key Usage: digitalSignature, keyEncipherment (для RSA) или digitalSignature (для ECC)
//   - Extended Key Usage: serverAuth
//   - Subject Alternative Name: минимум одно DNS имя или IP адрес
//
// Параметры:
//   - cfg: конфигурация шаблона
//
// Возвращает:
//   - *x509.Certificate: готовый шаблон сертификата
//   - error: ошибку, если конфигурация невалидна
func NewServerTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	if len(cfg.SANs) == 0 {
		return nil, fmt.Errorf("серверный сертификат требует хотя бы один SAN (DNS или IP)")
	}

	// Проверка наличия хотя бы одного DNS или IP SAN
	hasValidSAN := false
	for _, san := range cfg.SANs {
		if san.Type == "dns" || san.Type == "ip" {
			hasValidSAN = true
			break
		}
	}
	if !hasValidSAN {
		return nil, fmt.Errorf("серверный сертификат должен иметь хотя бы одно DNS имя или IP адрес в SAN")
	}

	// Разделение SAN по типам
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (критическое)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature, keyEncipherment (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		// Extended Key Usage: serverAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// Subject Alternative Name
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses,
		URIs:           uris,

		// Subject Key Identifier будет сгенерирован автоматически
		// Authority Key Identifier будет установлен издателем
	}

	return template, nil
}

// NewClientTemplate создаёт шаблон для сертификатов аутентификации клиента.
// Реализует требования PKI-8 для клиентских сертификатов:
//   - Basic Constraints: CA=FALSE (критическое)
//   - Key Usage: digitalSignature
//   - Extended Key Usage: clientAuth
//   - Subject Alternative Name: должен содержать email если предоставлен
//
// Параметры:
//   - cfg: конфигурация шаблона
//
// Возвращает:
//   - *x509.Certificate: готовый шаблон сертификата
//   - error: ошибку, если конфигурация невалидна
func NewClientTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	// Разделение SAN по типам
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (критическое)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature,

		// Extended Key Usage: clientAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		// Subject Alternative Name
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses,
		URIs:           uris,
	}

	return template, nil
}

// NewCodeSigningTemplate создаёт шаблон для сертификатов подписи кода.
// Реализует требования PKI-8 для сертификатов подписи кода:
//   - Basic Constraints: CA=FALSE (критическое)
//   - Key Usage: digitalSignature
//   - Extended Key Usage: codeSigning
//   - Subject Alternative Name: опционально, ограничен DNS/URI
//
// Параметры:
//   - cfg: конфигурация шаблона
//
// Возвращает:
//   - *x509.Certificate: готовый шаблон сертификата
//   - error: ошибку, если конфигурация невалидна
func NewCodeSigningTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	// Для подписи кода проверяем, что нет IP или email SAN
	for _, san := range cfg.SANs {
		if san.Type == "ip" || san.Type == "email" {
			return nil, fmt.Errorf("сертификат подписи кода не может содержать IP или email SAN")
		}
	}

	// Разделение SAN по типам
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (критическое)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature,

		// Extended Key Usage: codeSigning
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},

		// Subject Alternative Name (ограничен DNS/URI)
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,    // Должен быть пустым из-за проверки выше
		EmailAddresses: emailAddresses, // Должен быть пустым из-за проверки выше
		URIs:           uris,
	}

	return template, nil
}

// NewIntermediateCATemplate создаёт шаблон для сертификатов промежуточного CA.
// Реализует требования PKI-7:
//   - Basic Constraints: CA=TRUE, pathLenConstraint (критическое)
//   - Key Usage: keyCertSign, cRLSign (критическое)
//
// Параметры:
//   - cfg: конфигурация шаблона
//
// Возвращает:
//   - *x509.Certificate: готовый шаблон сертификата
func NewIntermediateCATemplate(cfg *TemplateConfig) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=TRUE, pathLenConstraint (критическое)
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            cfg.MaxPathLen,
		MaxPathLenZero:        cfg.MaxPathLen == 0,

		// Key Usage: keyCertSign, cRLSign (критическое)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		// Subject Key Identifier будет сгенерирован автоматически
		// Authority Key Identifier будет установлен издателем
	}

	return template
}

// ValidateTemplateCompatibility проверяет совместимость шаблона с предоставленными SAN.
// Выполняет проверки в зависимости от типа шаблона:
//   - Server: требует хотя бы один DNS или IP
//   - CodeSigning: запрещает IP и Email
//
// Параметры:
//   - tmplType: тип шаблона
//   - sans: срез SAN для проверки
//
// Возвращает:
//   - error: ошибку, если SAN несовместимы с шаблоном
func ValidateTemplateCompatibility(tmplType TemplateType, sans []SAN) error {
	switch tmplType {
	case Server:
		hasDNSorIP := false
		for _, san := range sans {
			if san.Type == "dns" || san.Type == "ip" {
				hasDNSorIP = true
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("серверный шаблон требует хотя бы один DNS или IP SAN")
		}

	case Client:
		// Клиентский шаблон может содержать любые типы SAN
		// Строгих требований нет

	case CodeSigning:
		for _, san := range sans {
			if san.Type == "ip" || san.Type == "email" {
				return fmt.Errorf("шаблон подписи кода не поддерживает IP или email SAN")
			}
		}
	}

	return nil
}

// ParseSANString парсит строку SAN в формате "тип:значение".
// Поддерживаемые типы: dns, ip, email, uri.
//
// Параметры:
//   - san: строка для парсинга
//
// Возвращает:
//   - SAN: структуру с типом и значением
//   - error: ошибку, если формат неверен
func ParseSANString(san string) (SAN, error) {
	parts := strings.SplitN(san, ":", 2)
	if len(parts) != 2 {
		return SAN{}, fmt.Errorf("неверный формат SAN: %s (ожидалось тип:значение)", san)
	}

	sanType := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	if value == "" {
		return SAN{}, fmt.Errorf("пустое значение SAN для типа %s", sanType)
	}

	// Валидация в зависимости от типа
	switch sanType {
	case "dns", "email", "uri":
		// Базовая валидация, фактический формат будет проверен при кодировании
	case "ip":
		if net.ParseIP(value) == nil {
			return SAN{}, fmt.Errorf("неверный IP адрес: %s", value)
		}
	default:
		return SAN{}, fmt.Errorf("неподдерживаемый тип SAN: %s (поддерживаются: dns, ip, email, uri)", sanType)
	}

	return SAN{Type: sanType, Value: value}, nil
}

// splitSANs разделяет SAN по типам и преобразует в форматы, ожидаемые x509.Certificate.
//
// Параметры:
//   - sans: срез SAN
//
// Возвращает:
//   - dnsNames: срез DNS имён
//   - ipAddresses: срез IP адресов
//   - emailAddresses: срез email адресов
//   - uris: срез URI
func splitSANs(sans []SAN) (dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL) {
	for _, san := range sans {
		switch san.Type {
		case "dns":
			dnsNames = append(dnsNames, san.Value)
		case "ip":
			if ip := net.ParseIP(san.Value); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		case "email":
			emailAddresses = append(emailAddresses, san.Value)
		case "uri":
			if u, err := url.Parse(san.Value); err == nil {
				uris = append(uris, u)
			}
		}
	}
	return dnsNames, ipAddresses, emailAddresses, uris
}
