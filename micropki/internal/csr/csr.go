// Package csr реализует операции с запросами на подписание сертификата (CSR)
// в соответствии со стандартом PKCS#10 (RFC 2986).
//
// Пакет предоставляет функциональность для:
//   - Генерации CSR для промежуточных центров сертификации
//   - Парсинга и проверки подписей CSR
//   - Извлечения информации из CSR (субъект, SAN, открытый ключ)
//   - Валидации совместимости CSR с шаблонами сертификатов
//
// Все CSR генерируются в формате PEM и включают необходимые расширения
// согласно требованиям PKI.
package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"micropki/micropki/internal/templates"
)

// CSRConfig содержит параметры конфигурации для генерации запроса на подписание сертификата.
type CSRConfig struct {
	// Subject - различающееся имя (DN) для запрашиваемого сертификата
	Subject *pkix.Name

	// SANs - альтернативные имена субъекта (DNS, IP, email, URI)
	SANs []templates.SAN

	// Key - закрытый ключ, соответствующий запрашиваемому сертификату
	Key crypto.PrivateKey

	// IsCA - флаг, указывающий, запрашивается ли сертификат центра сертификации
	IsCA bool

	// MaxPathLen - ограничение длины пути для CA (только если IsCA = true)
	MaxPathLen int
}

// GenerateIntermediateCSR генерирует CSR для промежуточного центра сертификации.
// Реализует требования PKI-6:
//   - Субъект DN как указано в конфигурации
//   - Открытый ключ из предоставленной ключевой пары
//   - Расширение Basic Constraints (CA=TRUE, pathLenConstraint при необходимости)
//
// Параметры:
//   - cfg: конфигурация CSR (субъект, ключ, флаги CA)
//
// Возвращает:
//   - []byte: CSR в формате PEM
//   - error: ошибку, если генерация не удалась
func GenerateIntermediateCSR(cfg *CSRConfig) ([]byte, error) {
	if cfg.Subject == nil {
		return nil, fmt.Errorf("субъект (subject) обязателен")
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("закрытый ключ (key) обязателен")
	}

	// Построение шаблона CSR
	template := &x509.CertificateRequest{
		Subject: *cfg.Subject,
		// Расширения будут добавлены отдельно
		Extensions: []pkix.Extension{},
	}

	// Добавление расширения Basic Constraints для CA (PKI-6)
	if cfg.IsCA {
		// OID для Basic Constraints: 2.5.29.19
		// ASN.1 кодировка для CA=TRUE с pathLenConstraint
		var extValue []byte
		if cfg.MaxPathLen >= 0 {
			// С ограничением длины пути
			extValue = []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, byte(cfg.MaxPathLen)}
		} else {
			// Без ограничения длины пути
			extValue = []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
		}

		template.Extensions = append(template.Extensions, pkix.Extension{
			Id:       []int{2, 5, 29, 19},
			Critical: true,
			Value:    extValue,
		})
	}

	// Генерация CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать CSR: %w", err)
	}

	// Кодирование в PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// ParseAndVerifyCSR парсит PEM-кодированный CSR и проверяет его подпись.
// Функция принимает CSR как в формате "CERTIFICATE REQUEST", так и
// в устаревшем формате "NEW CERTIFICATE REQUEST" для обратной совместимости.
//
// Параметры:
//   - csrPEM: CSR в формате PEM
//
// Возвращает:
//   - *x509.CertificateRequest: распарсенный и проверенный CSR
//   - error: ошибку, если декодирование или проверка подписи не удались
func ParseAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	// Декодирование PEM
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("неверный тип PEM: %s (ожидался CERTIFICATE REQUEST)", block.Type)
	}

	// Парсинг CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать CSR: %w", err)
	}

	// Проверка подписи
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("проверка подписи CSR не пройдена: %w", err)
	}

	return csr, nil
}

// ExtractPublicKey извлекает открытый ключ из CSR.
//
// Параметры:
//   - csr: распарсенный CSR
//
// Возвращает:
//   - crypto.PublicKey: открытый ключ
//   - error: ошибку, если CSR равен nil
func ExtractPublicKey(csr *x509.CertificateRequest) (crypto.PublicKey, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR равен nil")
	}
	return csr.PublicKey, nil
}

// IsCARequest проверяет, запрашивает ли CSR права центра сертификации.
// Анализирует наличие расширения Basic Constraints в CSR.
//
// Параметры:
//   - csr: распарсенный CSR
//
// Возвращает:
//   - true, если CSR содержит расширение Basic Constraints (признак запроса CA)
func IsCARequest(csr *x509.CertificateRequest) bool {
	for _, ext := range csr.Extensions {
		// Проверка расширения Basic Constraints (OID 2.5.29.19)
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			// Полный парсинг сложен, но наличие расширения достаточно для определения
			// запроса прав CA
			return true
		}
	}
	return false
}

// GetSubjectFromCSR возвращает субъект из CSR.
//
// Параметры:
//   - csr: распарсенный CSR
//
// Возвращает:
//   - *pkix.Name: указатель на структуру субъекта
func GetSubjectFromCSR(csr *x509.CertificateRequest) *pkix.Name {
	return &csr.Subject
}

// GetSANsFromCSR извлекает альтернативные имена субъекта из CSR.
// Поддерживает DNS имена, IP адреса, email адреса и URI.
//
// Параметры:
//   - csr: распарсенный CSR
//
// Возвращает:
//   - []templates.SAN: срез альтернативных имён
//   - error: ошибку, если извлечение не удалось
func GetSANsFromCSR(csr *x509.CertificateRequest) ([]templates.SAN, error) {
	var sans []templates.SAN

	// Добавление DNS имён
	for _, dns := range csr.DNSNames {
		sans = append(sans, templates.SAN{Type: "dns", Value: dns})
	}

	// Добавление IP адресов
	for _, ip := range csr.IPAddresses {
		sans = append(sans, templates.SAN{Type: "ip", Value: ip.String()})
	}

	// Добавление email адресов
	for _, email := range csr.EmailAddresses {
		sans = append(sans, templates.SAN{Type: "email", Value: email})
	}

	// Добавление URI
	for _, uri := range csr.URIs {
		sans = append(sans, templates.SAN{Type: "uri", Value: uri.String()})
	}

	return sans, nil
}

// ValidateCSRForTemplate проверяет совместимость CSR с заданным шаблоном сертификата.
// Выполняет следующие проверки:
//   - Совместимость типов SAN с шаблоном
//   - Для серверных сертификатов: наличие хотя бы одного DNS или IP имени
//   - Для сертификатов подписи кода: отсутствие запроса прав CA
//
// Параметры:
//   - csr: распарсенный CSR
//   - tmplType: тип шаблона (server, client, code_signing)
//
// Возвращает:
//   - error: ошибку, если CSR несовместим с шаблоном
func ValidateCSRForTemplate(csr *x509.CertificateRequest, tmplType templates.TemplateType) error {
	// Извлечение SAN из CSR
	sans, err := GetSANsFromCSR(csr)
	if err != nil {
		return fmt.Errorf("не удалось извлечь SAN: %w", err)
	}

	// Проверка совместимости шаблона
	if err := templates.ValidateTemplateCompatibility(tmplType, sans); err != nil {
		return fmt.Errorf("CSR несовместим с шаблоном %s: %w", tmplType, err)
	}

	// Дополнительные проверки в зависимости от типа
	switch tmplType {
	case templates.Server:
		// Серверные сертификаты должны иметь хотя бы одно DNS или IP имя
		hasDNSorIP := false
		for _, san := range sans {
			if san.Type == "dns" || san.Type == "ip" {
				hasDNSorIP = true
				break
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("серверный сертификат требует хотя бы одно DNS или IP имя")
		}

	case templates.CodeSigning:
		// Сертификаты подписи кода не должны запрашивать права CA
		if IsCARequest(csr) {
			return fmt.Errorf("сертификат подписи кода не может быть CA")
		}
	}

	return nil
}
