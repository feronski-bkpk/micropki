// Package certs обрабатывает операции с X.509 сертификатами.
// Пакет предоставляет функции для:
//   - Парсинга Distinguished Name (DN) из строковых представлений
//   - Генерации криптографически безопасных серийных номеров
//   - Создания шаблонов сертификатов для различных типов CA
//   - Загрузки и сохранения сертификатов в PEM-формате
//   - Проверки сертификатов и их соответствия ключам
//   - Извлечения информации о сертификатах и алгоритмах ключей
//
// Пакет реализует требования PKI-2, PKI-3 и поддерживает как RSA, так и ECC ключи.
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
// Поддерживаемые атрибуты:
//   - CN: Common Name
//   - O: Organization
//   - OU: Organizational Unit
//   - C: Country
//   - ST: State/Province
//   - L: Locality/City
//
// Неизвестные атрибуты сохраняются в ExtraNames для обратной совместимости.
//
// Возвращает ошибку, если строка пустая или имеет неверный формат.
func ParseDN(dn string) (*pkix.Name, error) {
	name := &pkix.Name{}

	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil, fmt.Errorf("пустая строка DN")
	}

	// Определение формата по первому символу
	if strings.HasPrefix(dn, "/") {
		return parseSlashFormat(dn, name)
	}
	return parseCommaFormat(dn, name)
}

// parseSlashFormat парсит DN в формате: /CN=.../O=.../C=...
// Внутренняя функция, не экспортируется.
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

		// Заполнение соответствующих полей в зависимости от ключа
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
// Внутренняя функция, не экспортируется.
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

		// Заполнение полей (для O, OU, C, ST, L может быть несколько значений)
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
// Реализация: используется 20 байт (160 бит) из криптографически безопасного
// генератора случайных чисел для обеспечения уникальности и непредсказуемости.
//
// Старший бит сбрасывается для гарантии положительного числа согласно X.509.
//
// Возвращает ошибку, если генератор случайных чисел недоступен.
func GenerateSerialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20) // 160 бит энтропии

	// Использование криптографически безопасного генератора случайных чисел
	_, err := rand.Read(serialBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}

	// Обеспечение положительного числа (сброс старшего бита)
	serialBytes[0] &= 0x7F

	return new(big.Int).SetBytes(serialBytes), nil
}

// NewRootCATemplate создает шаблон самоподписанного сертификата Root CA.
// Реализует требования PKI-2 и PKI-3:
//   - Версия X.509v3
//   - BasicConstraints: CA=TRUE (критическое расширение)
//   - KeyUsage: keyCertSign, cRLSign (критическое расширение)
//   - SubjectKeyIdentifier и AuthorityKeyIdentifier (генерируются автоматически)
//
// Параметры:
//   - subject, issuer: для самоподписанного сертификата должны совпадать
//   - serialNumber: уникальный серийный номер (из GenerateSerialNumber)
//   - notBefore, notAfter: период действия сертификата
//   - publicKey: открытый ключ сертификата
//
// Возвращает шаблон сертификата, готовый для подписания.
func NewRootCATemplate(subject, issuer *pkix.Name, serialNumber *big.Int,
	notBefore, notAfter time.Time, publicKey crypto.PublicKey) *x509.Certificate {

	return &x509.Certificate{
		// Версия 3 (значение 2 в структуре X.509)
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
		MaxPathLen:            -1, // -1 означает отсутствие ограничения длины пути

		// SubjectKeyIdentifier будет сгенерирован автоматически при создании
		// AuthorityKeyIdentifier будет установлен в то же значение для самоподписанного
	}
}

// CertificateMatchesPrivateKey проверяет соответствие сертификата приватному ключу.
// Используется для тестирования (TEST-2) и верификации.
//
// Поддерживает RSA и ECDSA ключи. Для RSA проверяет модуль и публичную экспоненту,
// для ECDSA - координаты точки и используемую кривую.
//
// Возвращает ошибку, если ключи не соответствуют или тип ключа не поддерживается.
func CertificateMatchesPrivateKey(cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	// Проверка соответствия публичного ключа в сертификате и приватного ключа
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		// Для RSA проверка модуля и публичной экспоненты
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("публичный ключ в сертификате не RSA")
		}
		if priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E {
			return fmt.Errorf("несоответствие RSA ключей")
		}

	case *ecdsa.PrivateKey:
		// Для ECDSA проверка координат точки на кривой
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
		return fmt.Errorf("неподдерживаемый тип ключа: %T", privateKey)
	}

	return nil
}

// GetCertificateInfo возвращает читаемую информацию о сертификате.
// Полезна для отладки и вывода пользователю в командной строке.
//
// Возвращает многострочную строку с информацией о:
//   - Субъекте и издателе
//   - Серийном номере
//   - Периоде действия
//   - Алгоритме подписи
//   - Расширениях (является ли CA, назначение ключа)
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
// Полезна для документов политики и вывода информации пользователю.
//
// Поддерживает RSA и ECDSA ключи. Для ECDSA определяет размер по кривой.
//
// Возвращает:
//   - algorithm: "RSA" или "ECC"
//   - size: размер ключа в битах
//   - error: если тип ключа не поддерживается
func GetKeyAlgorithm(pubKey crypto.PublicKey) (string, int, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen(), nil
	case *ecdsa.PublicKey:
		// Определение размера ключа по используемой кривой
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
// Выполняет следующие проверки:
//   - Издатель должен совпадать с субъектом
//   - Подпись должна быть корректной (проверка самим собой)
//   - Должен быть CA (IsCA=true)
//   - Должен иметь правильные KeyUsage (keyCertSign и cRLSign)
//
// Возвращает ошибку, если любая из проверок не пройдена.
func VerifySelfSigned(cert *x509.Certificate) error {
	// Для самоподписанного сертификата издатель должен совпадать с субъектом
	if cert.Issuer.String() != cert.Subject.String() {
		return fmt.Errorf("издатель не совпадает с субъектом для самоподписанного сертификата")
	}

	// Проверка подписи
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("проверка подписи не пройдена: %w", err)
	}

	// Проверка обязательных расширений для CA
	if !cert.IsCA {
		return fmt.Errorf("сертификат CA должен иметь IsCA=true")
	}

	// Проверка KeyUsage
	requiredKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("отсутствуют обязательные KeyUsage: keyCertSign и cRLSign")
	}

	return nil
}

// VerifyCertificate проверяет сертификат относительно издателя.
// Выполняет:
//   - Проверку подписи издателем
//   - Проверку срока действия
//
// Возвращает ошибку, если любая из проверок не пройдена.
func VerifyCertificate(cert *x509.Certificate, issuer *x509.Certificate) error {
	// Проверка подписи
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("проверка подписи не пройдена: %w", err)
	}

	// Проверка срока действия
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("сертификат недействителен в текущее время")
	}

	return nil
}

// LoadCertificate загружает и парсит PEM-сертификат из файла.
// Ожидает файл в формате PEM с блоком типа "CERTIFICATE".
//
// Возвращает ошибку, если:
//   - Файл не может быть прочитан
//   - PEM-декодирование не удалось
//   - Тип блока не CERTIFICATE
//   - Парсинг сертификата не удался
func LoadCertificate(path string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл сертификата: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM сертификат")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("неверный тип PEM: %s (ожидался CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать сертификат: %w", err)
	}

	return cert, nil
}

// SaveCertificate сохраняет DER-сертификат в PEM-файл.
// Создаёт файл с правами доступа 0644 (rw-r--r--).
//
// Возвращает ошибку, если запись в файл не удалась.
func SaveCertificate(certDER []byte, path string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return os.WriteFile(path, certPEM, 0644)
}
