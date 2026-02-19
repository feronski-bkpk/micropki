// Package san реализует парсинг и валидацию альтернативных имён субъекта (SAN)
// в соответствии с RFC 5280 (Internet X.509 Public Key Infrastructure).
//
// Пакет поддерживает четыре типа SAN:
//   - DNS имена (dns)
//   - IP адреса (ip)
//   - Email адреса (email)
//   - URI (uri)
//
// Все операции включают валидацию формата в соответствии со спецификациями.
package san

import (
	"fmt"
	"net"
	"strings"

	"micropki/micropki/internal/templates"
)

// SANType определяет тип альтернативного имени субъекта.
// Соответствует типам, определённым в RFC 5280, раздел 4.2.1.6.
type SANType string

const (
	// DNS представляет доменное имя (например, "example.com")
	DNS SANType = "dns"

	// IP представляет IPv4 или IPv6 адрес
	IP SANType = "ip"

	// Email представляет email адрес в формате RFC 822
	Email SANType = "email"

	// URI представляет унифицированный идентификатор ресурса
	URI SANType = "uri"
)

// SAN представляет разобранное альтернативное имя субъекта.
// Содержит тип и значение, прошедшее базовую валидацию.
type SAN struct {
	// Type - тип SAN (dns, ip, email, uri)
	Type SANType

	// Value - значение SAN в строковом представлении
	Value string
}

// ParseSAN парсит строку в формате "тип:значение".
// Поддерживаемые типы: dns, ip, email, uri.
//
// Параметры:
//   - san: строка для парсинга (например, "dns:example.com")
//
// Возвращает:
//   - SAN: структуру с типом и значением
//   - error: ошибку, если формат неверен или валидация не пройдена
//
// Примеры:
//   - "dns:example.com" → SAN{Type: DNS, Value: "example.com"}
//   - "ip:192.168.1.1" → SAN{Type: IP, Value: "192.168.1.1"}
//   - "email:user@example.com" → SAN{Type: Email, Value: "user@example.com"}
//   - "uri:https://example.com" → SAN{Type: URI, Value: "https://example.com"}
func ParseSAN(san string) (SAN, error) {
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
	case "dns":
		// Базовая проверка DNS - непустое значение
		if len(value) == 0 {
			return SAN{}, fmt.Errorf("пустое DNS имя")
		}
		// Дополнительная валидация может быть добавлена позже

	case "ip":
		if net.ParseIP(value) == nil {
			return SAN{}, fmt.Errorf("неверный IP адрес: %s", value)
		}

	case "email":
		// Базовая проверка email - наличие @
		if !strings.Contains(value, "@") {
			return SAN{}, fmt.Errorf("неверный email адрес: %s", value)
		}
		// Полная валидация по RFC 822 может быть добавлена позже

	case "uri":
		// Базовая проверка URI - наличие схемы (://)
		if !strings.Contains(value, "://") {
			return SAN{}, fmt.Errorf("неверный URI: %s (должен содержать схему)", value)
		}

	default:
		return SAN{}, fmt.Errorf("неподдерживаемый тип SAN: %s (поддерживаются: dns, ip, email, uri)", sanType)
	}

	return SAN{
		Type:  SANType(sanType),
		Value: value,
	}, nil
}

// ValidateSANTypes проверяет совместимость предоставленных SAN с шаблоном сертификата.
// Выполняет проверки в зависимости от типа сертификата:
//   - Server: требует хотя бы один DNS или IP
//   - Client: любые типы допустимы
//   - CodeSigning: запрещает IP и Email
//
// Параметры:
//   - tmplType: тип шаблона сертификата
//   - sans: срез строк SAN для проверки
//
// Возвращает:
//   - error: ошибку, если SAN несовместимы с шаблоном
func ValidateSANTypes(tmplType templates.TemplateType, sans []string) error {
	if len(sans) == 0 {
		// Серверные сертификаты требуют хотя бы один SAN
		if tmplType == templates.Server {
			return fmt.Errorf("серверный сертификат требует хотя бы один SAN (DNS или IP)")
		}
		// Клиентские сертификаты и сертификаты подписи кода могут быть без SAN
		return nil
	}

	// Парсинг и валидация каждого SAN
	parsedSANs := make([]SAN, 0, len(sans))
	for _, san := range sans {
		parsed, err := ParseSAN(san)
		if err != nil {
			return fmt.Errorf("неверный SAN '%s': %w", san, err)
		}
		parsedSANs = append(parsedSANs, parsed)
	}

	// Проверки, специфичные для типа шаблона
	switch tmplType {
	case templates.Server:
		// Серверный сертификат должен иметь хотя бы один DNS или IP
		hasDNSorIP := false
		for _, san := range parsedSANs {
			if san.Type == DNS || san.Type == IP {
				hasDNSorIP = true
				break
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("серверный сертификат требует хотя бы один DNS или IP SAN")
		}

	case templates.Client:
		// Клиентский сертификат может иметь любые типы
		// Дополнительная валидация не требуется

	case templates.CodeSigning:
		// Сертификат подписи кода не должен иметь IP или Email SAN
		for _, san := range parsedSANs {
			if san.Type == IP {
				return fmt.Errorf("сертификат подписи кода не может содержать IP SAN")
			}
			if san.Type == Email {
				return fmt.Errorf("сертификат подписи кода не может содержать Email SAN")
			}
		}
	}

	return nil
}

// ExtractSANs извлекает SAN из компонентов сертификата или запроса.
// Функция-помощник для получения SAN в единообразном формате.
//
// Параметры:
//   - dnsNames: срез DNS имён
//   - ipAddresses: срез IP адресов
//   - emailAddresses: срез email адресов
//   - uris: срез URI строк
//
// Возвращает:
//   - []SAN: срез структур SAN
func ExtractSANs(dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []string) []SAN {
	var sans []SAN

	for _, dns := range dnsNames {
		sans = append(sans, SAN{Type: DNS, Value: dns})
	}

	for _, ip := range ipAddresses {
		sans = append(sans, SAN{Type: IP, Value: ip.String()})
	}

	for _, email := range emailAddresses {
		sans = append(sans, SAN{Type: Email, Value: email})
	}

	for _, uri := range uris {
		sans = append(sans, SAN{Type: URI, Value: uri})
	}

	return sans
}

// String возвращает строковое представление SAN в формате "тип:значение".
// Реализует интерфейс fmt.Stringer.
func (s SAN) String() string {
	return fmt.Sprintf("%s:%s", s.Type, s.Value)
}
