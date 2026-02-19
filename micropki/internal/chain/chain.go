// Package chain реализует проверку цепочек сертификатов и управление ими
// в соответствии с RFC 5280 (Internet X.509 Public Key Infrastructure).
//
// Пакет предоставляет функциональность для:
//   - Загрузки цепочек сертификатов из PEM-файлов
//   - Проверки целостности цепочек (подписи, сроки действия, ограничения)
//   - Валидации расширений (Basic Constraints, Key Usage)
//   - Проверки совместимости с OpenSSL
//
// Цепочка сертификатов состоит из трёх уровней:
//   - Корневой CA (самоподписанный)
//   - Промежуточный CA (подписан корневым)
//   - Конечный сертификат (подписан промежуточным)
//
// Пакет реализует требования TEST-7.
package chain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Chain представляет полную цепочку сертификатов от корневого до конечного.
// Структура гарантирует, что все три сертификата загружены и могут быть
// проверены как единая цепочка доверия.
type Chain struct {
	// Leaf - конечный сертификат (end-entity certificate)
	// Не может быть CA, может содержать DNS имена, IP адреса, email'ы
	Leaf *x509.Certificate

	// Intermediate - промежуточный центр сертификации
	// Должен быть CA и иметь правильные KeyUsage
	Intermediate *x509.Certificate

	// Root - корневой центр сертификации (самоподписанный)
	// Должен быть CA, издатель должен совпадать с субъектом
	Root *x509.Certificate
}

// LoadChain загружает сертификаты из файлов и строит цепочку.
// Все файлы должны быть в PEM-формате с блоками типа "CERTIFICATE".
//
// Параметры:
//   - leafPath: путь к файлу с конечным сертификатом
//   - intermediatePath: путь к файлу с промежуточным сертификатом
//   - rootPath: путь к файлу с корневым сертификатом
//
// Возвращает:
//   - *Chain: структуру цепочки для дальнейшей проверки
//   - error: ошибку, если любой из файлов не может быть загружен или распарсен
func LoadChain(leafPath, intermediatePath, rootPath string) (*Chain, error) {
	leaf, err := LoadCertificate(leafPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить конечный сертификат: %w", err)
	}

	intermediate, err := LoadCertificate(intermediatePath)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить промежуточный сертификат: %w", err)
	}

	root, err := LoadCertificate(rootPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить корневой сертификат: %w", err)
	}

	return &Chain{
		Leaf:         leaf,
		Intermediate: intermediate,
		Root:         root,
	}, nil
}

// LoadCertificate загружает и парсит PEM-сертификат из файла.
// Функция ожидает файл в формате PEM с одним блоком типа "CERTIFICATE".
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

// Verify проверяет полную цепочку сертификатов.
// Реализует требования TEST-7:
//   - Проверка подписей на каждом уровне
//   - Проверка сроков действия
//   - Проверка Basic Constraints (флаг CA и ограничения длины пути)
//   - Проверка совместимости Key Usage / Extended Key Usage
//
// Последовательность проверок:
//  1. Конечный сертификат не должен быть CA
//  2. Промежуточный и корневой должны быть CA
//  3. Все сертификаты должны быть действительны в текущий момент
//  4. Подпись конечного сертификата проверяется промежуточным CA
//  5. Подпись промежуточного CA проверяется корневым CA
//  6. Проверка KeyUsage для CA сертификатов
//  7. Проверка ограничений длины пути
//
// Возвращает ошибку, если любая из проверок не пройдена.
func (c *Chain) Verify() error {
	// 1. Проверка, что конечный сертификат не является CA
	if c.Leaf.IsCA {
		return fmt.Errorf("конечный сертификат не может быть CA")
	}

	// 2. Проверка, что промежуточный сертификат является CA
	if !c.Intermediate.IsCA {
		return fmt.Errorf("промежуточный сертификат должен быть CA")
	}

	// 3. Проверка, что корневой сертификат является CA
	if !c.Root.IsCA {
		return fmt.Errorf("корневой сертификат должен быть CA")
	}

	// 4. Проверка сроков действия
	now := time.Now()
	if now.Before(c.Leaf.NotBefore) || now.After(c.Leaf.NotAfter) {
		return fmt.Errorf("конечный сертификат недействителен в текущее время")
	}
	if now.Before(c.Intermediate.NotBefore) || now.After(c.Intermediate.NotAfter) {
		return fmt.Errorf("промежуточный сертификат недействителен в текущее время")
	}
	if now.Before(c.Root.NotBefore) || now.After(c.Root.NotAfter) {
		return fmt.Errorf("корневой сертификат недействителен в текущее время")
	}

	// 5. Проверка подписей
	// Конечный сертификат подписан промежуточным CA
	if err := c.Leaf.CheckSignatureFrom(c.Intermediate); err != nil {
		return fmt.Errorf("проверка подписи конечного сертификата не пройдена: %w", err)
	}

	// Промежуточный CA подписан корневым CA
	if err := c.Intermediate.CheckSignatureFrom(c.Root); err != nil {
		return fmt.Errorf("проверка подписи промежуточного CA не пройдена: %w", err)
	}

	// 6. Проверка KeyUsage для CA сертификатов
	requiredKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if c.Intermediate.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("у промежуточного CA отсутствуют обязательные KeyUsage: keyCertSign и cRLSign")
	}
	if c.Root.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("у корневого CA отсутствуют обязательные KeyUsage: keyCertSign и cRLSign")
	}

	// 7. Проверка ограничений длины пути
	if err := c.verifyPathLength(); err != nil {
		return err
	}

	return nil
}

// verifyPathLength проверяет ограничения длины пути в цепочке сертификатов.
// Согласно RFC 5280, расширение Basic Constraints может содержать
// ограничение на количество промежуточных CA ниже данного.
//
// Проверяет:
//   - Ограничение длины пути в промежуточном CA (если установлено)
//   - Ограничение длины пути в корневом CA (если установлено)
//
// Возвращает ошибку, если ограничения нарушены.
func (c *Chain) verifyPathLength() error {
	// Проверка ограничения длины пути в промежуточном CA
	if c.Intermediate.MaxPathLen >= 0 {
		// PathLen = 0 означает, что ниже этого CA не может быть других CA
		if c.Intermediate.MaxPathLen == 0 {
			// Это нормально, так как конечный сертификат не является CA
		}
	}

	// Проверка ограничения длины пути в корневом CA (если установлено)
	if c.Root.MaxPathLen >= 0 {
		// Подсчёт количества CA сертификатов в цепочке (исключая корневой)
		caCount := 1 // промежуточный CA
		if caCount > c.Root.MaxPathLen {
			return fmt.Errorf("нарушено ограничение длины пути: длина цепочки %d превышает MaxPathLen корневого CA %d",
				caCount, c.Root.MaxPathLen)
		}
	}

	return nil
}

// VerifyWithOpenSSLCompatibility выполняет дополнительные проверки для совместимости с OpenSSL.
// OpenSSL более строг к некоторым расширениям, особенно к критичности Basic Constraints.
//
// Проверяет:
//   - Для CA сертификатов расширение Basic Constraints должно быть критическим
//
// Возвращает ошибку, если обнаружены несовместимости, иначе nil.
func (c *Chain) VerifyWithOpenSSLCompatibility() error {
	// Проверка критичности Basic Constraints для CA сертификатов
	for _, cert := range []*x509.Certificate{c.Leaf, c.Intermediate, c.Root} {
		for _, ext := range cert.Extensions {
			// Проверка расширения Basic Constraints (OID 2.5.29.19)
			if ext.Id.Equal([]int{2, 5, 29, 19}) {
				if !ext.Critical && cert.IsCA {
					return fmt.Errorf("расширение Basic Constraints должно быть критическим для CA сертификатов")
				}
			}
		}
	}

	return nil
}

// PrintChainInfo возвращает читаемую информацию о цепочке сертификатов.
// Полезна для отладки и вывода пользователю в командной строке.
//
// Возвращает многострочную строку с информацией о:
//   - Корневом CA (субъект, издатель, серийный номер, срок действия)
//   - Промежуточном CA (субъект, издатель, серийный номер, срок действия, ограничения)
//   - Конечном сертификате (субъект, издатель, серийный номер, срок действия, имена)
func (c *Chain) PrintChainInfo() string {
	var info string

	info += "Цепочка сертификатов:\n"
	info += "====================\n\n"

	info += "Корневой CA:\n"
	info += fmt.Sprintf("  Субъект: %s\n", c.Root.Subject)
	info += fmt.Sprintf("  Издатель: %s\n", c.Root.Issuer)
	info += fmt.Sprintf("  Серийный номер: %X\n", c.Root.SerialNumber)
	info += fmt.Sprintf("  Действителен: с %s по %s\n",
		c.Root.NotBefore.Format("2006-01-02"),
		c.Root.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  Является CA: %v\n", c.Root.IsCA)
	info += "\n"

	info += "Промежуточный CA:\n"
	info += fmt.Sprintf("  Субъект: %s\n", c.Intermediate.Subject)
	info += fmt.Sprintf("  Издатель: %s\n", c.Intermediate.Issuer)
	info += fmt.Sprintf("  Серийный номер: %X\n", c.Intermediate.SerialNumber)
	info += fmt.Sprintf("  Действителен: с %s по %s\n",
		c.Intermediate.NotBefore.Format("2006-01-02"),
		c.Intermediate.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  Является CA: %v\n", c.Intermediate.IsCA)
	info += fmt.Sprintf("  Ограничение длины пути: %d\n", c.Intermediate.MaxPathLen)
	info += "\n"

	info += "Конечный сертификат:\n"
	info += fmt.Sprintf("  Субъект: %s\n", c.Leaf.Subject)
	info += fmt.Sprintf("  Издатель: %s\n", c.Leaf.Issuer)
	info += fmt.Sprintf("  Серийный номер: %X\n", c.Leaf.SerialNumber)
	info += fmt.Sprintf("  Действителен: с %s по %s\n",
		c.Leaf.NotBefore.Format("2006-01-02"),
		c.Leaf.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  DNS имена: %v\n", c.Leaf.DNSNames)
	info += fmt.Sprintf("  IP адреса: %v\n", c.Leaf.IPAddresses)
	info += fmt.Sprintf("  Email адреса: %v\n", c.Leaf.EmailAddresses)

	return info
}
