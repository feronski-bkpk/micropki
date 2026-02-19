// Package ca реализует операции центра сертификации (Certificate Authority).
// Этот файл содержит реализацию выпуска промежуточных CA и конечных сертификатов.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/micropki/internal/certs"
	cryptolib "micropki/micropki/internal/crypto" // алиас для избежания конфликта имён с стандартным crypto
	"micropki/micropki/internal/csr"
	"micropki/micropki/internal/templates"
)

// CAConfig содержит параметры конфигурации для создания промежуточного CA.
// Все поля должны быть заполнены перед вызовом IssueIntermediate.
type CAConfig struct {
	// RootCertPath - путь к PEM-файлу сертификата корневого CA
	RootCertPath string
	// RootKeyPath - путь к PEM-файлу зашифрованного закрытого ключа корневого CA
	RootKeyPath string
	// RootPassphrase - парольная фраза для расшифровки ключа корневого CA
	RootPassphrase []byte
	// Subject - различающееся имя (DN) для нового промежуточного CA
	Subject *pkix.Name
	// KeyType - тип ключа: "rsa" или "ecc"
	KeyType string
	// KeySize - размер ключа: 4096 для RSA, 384 для ECC
	KeySize int
	// Passphrase - парольная фраза для шифрования ключа промежуточного CA
	Passphrase []byte
	// OutDir - директория для сохранения выходных файлов
	OutDir string
	// ValidityDays - срок действия сертификата в днях
	ValidityDays int
	// PathLen - ограничение длины пути (максимальное количество промежуточных CA ниже)
	PathLen int
}

// IssueIntermediate создаёт новый промежуточный CA, подписанный корневым CA.
// Функция выполняет следующие шаги:
//  1. Загрузка сертификата и ключа корневого CA
//  2. Генерация ключевой пары для промежуточного CA
//  3. Генерация серийного номера
//  4. Создание шаблона сертификата промежуточного CA
//  5. Подписание сертификата корневым CA
//  6. Проверка созданного сертификата
//  7. Сохранение зашифрованного закрытого ключа
//  8. Сохранение сертификата
//  9. Обновление документа политики
//
// Функция соответствует требованиям CLI-7, PKI-6 и PKI-7.
//
// Возвращает ошибку, если какой-либо из шагов завершился неудачей.
func IssueIntermediate(cfg *CAConfig) error {
	// 1. Загрузка сертификата и ключа корневого CA
	rootCert, err := certs.LoadCertificate(cfg.RootCertPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат корневого CA: %w", err)
	}

	rootKey, err := cryptolib.LoadEncryptedPrivateKey(cfg.RootKeyPath, cfg.RootPassphrase)
	if err != nil {
		return fmt.Errorf("не удалось загрузить закрытый ключ корневого CA: %w", err)
	}

	// 2. Генерация ключевой пары промежуточного CA
	keyPair, err := cryptolib.GenerateKeyPair(cfg.KeyType, cfg.KeySize)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать ключевую пару промежуточного CA: %w", err)
	}

	// 3. Генерация серийного номера
	serialNumber, err := templates.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	// 4. Установка периода действия
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, cfg.ValidityDays)

	// 5. Создание шаблона промежуточного CA
	tmplCfg := &templates.TemplateConfig{
		Subject:      cfg.Subject,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    keyPair.PublicKey,
		IsCA:         true,
		MaxPathLen:   cfg.PathLen,
	}

	template := templates.NewIntermediateCATemplate(tmplCfg)

	// 6. Создание сертификата (корневой CA подписывает промежуточный)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,          // шаблон нового сертификата
		rootCert,          // сертификат издателя (корневой CA)
		keyPair.PublicKey, // открытый ключ нового сертификата
		rootKey,           // закрытый ключ издателя
	)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат промежуточного CA: %w", err)
	}

	// 7. Парсинг созданного сертификата для проверки
	intermediateCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("не удалось разобрать созданный сертификат: %w", err)
	}

	// 8. Проверка подписи сертификата
	if err := intermediateCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("проверка подписи созданного сертификата не пройдена: %w", err)
	}

	// 9. Сохранение зашифрованного закрытого ключа
	privateKeyPath := filepath.Join(cfg.OutDir, "private", "intermediate.key.pem")
	if err := cryptolib.SaveEncryptedPrivateKey(keyPair.PrivateKey, privateKeyPath, cfg.Passphrase); err != nil {
		return fmt.Errorf("не удалось сохранить закрытый ключ промежуточного CA: %w", err)
	}
	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return fmt.Errorf("не удалось установить права доступа к ключу: %w", err)
	}

	// 10. Сохранение сертификата
	certPath := filepath.Join(cfg.OutDir, "certs", "intermediate.cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return fmt.Errorf("не удалось сохранить сертификат промежуточного CA: %w", err)
	}

	// 11. Обновление документа политики
	if err := updatePolicyWithIntermediate(cfg.OutDir, intermediateCert, cfg); err != nil {
		return fmt.Errorf("не удалось обновить документ политики: %w", err)
	}

	fmt.Printf("\nПромежуточный CA успешно создан!\n")
	fmt.Printf("Сертификат: %s\n", certPath)
	fmt.Printf("Закрытый ключ: %s (зашифрован)\n", privateKeyPath)
	fmt.Printf("Серийный номер: %X\n", intermediateCert.SerialNumber)

	return nil
}

// IssueCertificateConfig содержит параметры конфигурации для выпуска
// конечного сертификата (end-entity certificate).
type IssueCertificateConfig struct {
	// CACertPath - путь к PEM-файлу сертификата промежуточного CA
	CACertPath string
	// CAKeyPath - путь к PEM-файлу зашифрованного ключа промежуточного CA
	CAKeyPath string
	// CAPassphrase - парольная фраза для расшифровки ключа промежуточного CA
	CAPassphrase []byte
	// Template - тип сертификата: server, client или code_signing
	Template templates.TemplateType
	// Subject - различающееся имя (DN) для нового сертификата
	Subject *pkix.Name
	// SANs - альтернативные имена субъекта (DNS, IP, email, URI)
	SANs []templates.SAN
	// CSRPath - опциональный путь к внешнему CSR для подписания
	CSRPath string
	// OutDir - директория для сохранения выходных файлов
	OutDir string
	// ValidityDays - срок действия сертификата в днях
	ValidityDays int
	// KeyType - тип ключа для внутренней генерации: "rsa" или "ecc"
	KeyType string
	// KeySize - размер ключа для внутренней генерации
	KeySize int
}

// IssueCertificate выпускает конечный сертификат, подписанный промежуточным CA.
// Функция поддерживает два режима работы:
//  1. Генерация новой ключевой пары и создание сертификата
//  2. Подписание внешнего CSR (без генерации ключа)
//
// Функция выполняет следующие шаги:
//  1. Загрузка сертификата и ключа промежуточного CA
//  2. Проверка совместимости шаблона с SAN
//  3. Обработка CSR или генерация новой ключевой пары
//  4. Генерация серийного номера
//  5. Создание шаблона сертификата согласно типу
//  6. Подписание сертификата промежуточным CA
//  7. Сохранение сертификата
//  8. Сохранение закрытого ключа (если генерировался)
//
// Функция соответствует требованиям CLI-8, PKI-8, PKI-9 и PKI-11.
//
// Возвращает ошибку, если какой-либо из шагов завершился неудачей.
func IssueCertificate(cfg *IssueCertificateConfig) error {
	// 1. Загрузка сертификата и ключа CA
	caCert, err := certs.LoadCertificate(cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат CA: %w", err)
	}

	caKey, err := cryptolib.LoadEncryptedPrivateKey(cfg.CAKeyPath, cfg.CAPassphrase)
	if err != nil {
		return fmt.Errorf("не удалось загрузить закрытый ключ CA: %w", err)
	}

	// 2. Проверка CA (опционально, но рекомендуется)
	if caCert.IsCA && caCert.MaxPathLen == 0 {
		// Это нормально - промежуточный CA с pathlen=0 может выпускать конечные сертификаты
	}

	// 3. Проверка совместимости шаблона с SAN
	if err := templates.ValidateTemplateCompatibility(cfg.Template, cfg.SANs); err != nil {
		return fmt.Errorf("проверка шаблона не пройдена: %w", err)
	}

	var publicKey crypto.PublicKey
	var privateKey crypto.PrivateKey
	var certSubject *pkix.Name
	var certSANs []templates.SAN

	// 4. Обработка CSR или генерация новой ключевой пары
	if cfg.CSRPath != "" {
		// Подписание внешнего CSR
		certSubject, certSANs, publicKey, err = processExternalCSR(cfg)
		if err != nil {
			return fmt.Errorf("не удалось обработать внешний CSR: %w", err)
		}
		// Для внешнего CSR закрытый ключ не сохраняется
	} else {
		// Генерация новой ключевой пары
		keyPair, err := cryptolib.GenerateKeyPair(cfg.KeyType, cfg.KeySize)
		if err != nil {
			return fmt.Errorf("не удалось сгенерировать ключевую пару: %w", err)
		}
		publicKey = keyPair.PublicKey
		privateKey = keyPair.PrivateKey
		certSubject = cfg.Subject
		certSANs = cfg.SANs
	}

	// 5. Генерация серийного номера
	serialNumber, err := templates.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	// 6. Установка периода действия
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, cfg.ValidityDays)

	// 7. Создание шаблона согласно типу
	tmplCfg := &templates.TemplateConfig{
		Subject:      certSubject,
		SANs:         certSANs,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    publicKey,
	}

	var template *x509.Certificate
	switch cfg.Template {
	case templates.Server:
		template, err = templates.NewServerTemplate(tmplCfg)
	case templates.Client:
		template, err = templates.NewClientTemplate(tmplCfg)
	case templates.CodeSigning:
		template, err = templates.NewCodeSigningTemplate(tmplCfg)
	default:
		return fmt.Errorf("неподдерживаемый тип шаблона: %s", cfg.Template)
	}
	if err != nil {
		return fmt.Errorf("не удалось создать шаблон: %w", err)
	}

	// 8. Создание сертификата (CA подписывает новый сертификат)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,  // шаблон нового сертификата
		caCert,    // сертификат издателя (промежуточный CA)
		publicKey, // открытый ключ нового сертификата
		caKey,     // закрытый ключ издателя
	)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}

	// 9. Парсинг созданного сертификата для получения информации для имени файла
	newCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("не удалось разобрать созданный сертификат: %w", err)
	}

	// 10. Определение имени файла на основе CN или первого DNS имени
	filename := generateCertFilename(newCert, cfg.Template)

	// 11. Сохранение сертификата
	certPath := filepath.Join(cfg.OutDir, filename+".cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return fmt.Errorf("не удалось сохранить сертификат: %w", err)
	}

	// 12. Сохранение закрытого ключа, если он был сгенерирован
	var keyPath string
	if privateKey != nil {
		keyPath = filepath.Join(cfg.OutDir, filename+".key.pem")
		if err := cryptolib.SavePrivateKeyUnencrypted(privateKey, keyPath); err != nil {
			return fmt.Errorf("не удалось сохранить закрытый ключ: %w", err)
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			return fmt.Errorf("не удалось установить права доступа к ключу: %w", err)
		}
		fmt.Printf("ПРЕДУПРЕЖДЕНИЕ: Закрытый ключ сохранён без шифрования в %s\n", keyPath)
	}

	// 13. Логирование выпуска (для аудита)
	fmt.Printf("\nСертификат успешно выпущен!\n")
	fmt.Printf("Тип: %s\n", cfg.Template)
	fmt.Printf("Сертификат: %s\n", certPath)
	if keyPath != "" {
		fmt.Printf("Закрытый ключ: %s (НЕЗАШИФРОВАН)\n", keyPath)
	}
	fmt.Printf("Серийный номер: %X\n", newCert.SerialNumber)
	if len(cfg.SANs) > 0 {
		fmt.Printf("Альтернативные имена субъекта:\n")
		for _, san := range cfg.SANs {
			fmt.Printf("  %s: %s\n", san.Type, san.Value)
		}
	}

	return nil
}

// processExternalCSR обрабатывает внешний CSR для подписания.
// Функция выполняет:
//  1. Чтение и парсинг CSR
//  2. Проверку подписи CSR
//  3. Извлечение субъекта, SAN и открытого ключа
//  4. Проверку совместимости с шаблоном
//
// Возвращает субъект, SAN, открытый ключ или ошибку.
func processExternalCSR(cfg *IssueCertificateConfig) (*pkix.Name, []templates.SAN, crypto.PublicKey, error) {
	// Чтение файла CSR
	csrPEM, err := os.ReadFile(cfg.CSRPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось прочитать файл CSR: %w", err)
	}

	// Парсинг и проверка CSR
	parsedCSR, err := csr.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось разобрать CSR: %w", err)
	}

	// Проверка, не запрашивает ли CSR права CA (должно быть отклонено для конечных сертификатов)
	if csr.IsCARequest(parsedCSR) {
		return nil, nil, nil, fmt.Errorf("CSR запрашивает CA=true - не разрешено для конечных сертификатов")
	}

	// Извлечение субъекта из CSR
	subject := csr.GetSubjectFromCSR(parsedCSR)

	// Извлечение SAN из CSR
	sans, err := csr.GetSANsFromCSR(parsedCSR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось извлечь SAN из CSR: %w", err)
	}

	// Проверка совместимости CSR с шаблоном
	if err := csr.ValidateCSRForTemplate(parsedCSR, cfg.Template); err != nil {
		return nil, nil, nil, fmt.Errorf("CSR несовместим с шаблоном: %w", err)
	}

	// Извлечение открытого ключа
	publicKey, err := csr.ExtractPublicKey(parsedCSR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось извлечь открытый ключ: %w", err)
	}

	return subject, sans, publicKey, nil
}

// generateCertFilename создаёт имя файла на основе содержимого сертификата.
// Стратегия именования:
//  1. Для серверных сертификатов - первое DNS имя
//  2. Для клиентских сертификатов - первый email
//  3. Иначе - Common Name
//  4. В крайнем случае - серийный номер
//
// Возвращает безопасное для файловой системы имя.
func generateCertFilename(cert *x509.Certificate, tmplType templates.TemplateType) string {
	// Попытка использовать первое DNS имя для серверных сертификатов
	if tmplType == templates.Server && len(cert.DNSNames) > 0 {
		return sanitizeFilename(cert.DNSNames[0])
	}
	// Попытка использовать email для клиентских сертификатов
	if tmplType == templates.Client && len(cert.EmailAddresses) > 0 {
		return sanitizeFilename(cert.EmailAddresses[0])
	}
	// Использование Common Name
	if cert.Subject.CommonName != "" {
		return sanitizeFilename(cert.Subject.CommonName)
	}
	// В крайнем случае - серийный номер
	return fmt.Sprintf("cert-%X", cert.SerialNumber)
}

// sanitizeFilename удаляет символы, небезопасные для имён файлов.
// Заменяет проблемные символы на подчёркивание.
// Разрешённые символы: a-z, A-Z, 0-9, '-', '.'
func sanitizeFilename(name string) string {
	// Замена проблемных символов на подчёркивание
	result := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// updatePolicyWithIntermediate добавляет информацию о промежуточном CA в policy.txt.
// Функция добавляет новый раздел в существующий документ политики с деталями
// созданного промежуточного CA.
//
// Возвращает ошибку, если не удаётся прочитать или записать файл.
func updatePolicyWithIntermediate(outDir string, cert *x509.Certificate, cfg *CAConfig) error {
	policyPath := filepath.Join(outDir, "policy.txt")

	// Чтение существующей политики или создание новой
	var content []byte
	if _, err := os.Stat(policyPath); err == nil {
		content, err = os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("не удалось прочитать существующую политику: %w", err)
		}
	}

	// Добавление секции промежуточного CA
	policy := string(content)
	policy += "\n\n"
	policy += "ПРОМЕЖУТОЧНЫЙ CA\n"
	policy += strings.Repeat("=", 30) + "\n\n"
	policy += fmt.Sprintf("Дата создания: %s\n", time.Now().UTC().Format(time.RFC3339))
	policy += fmt.Sprintf("Субъект: %s\n", cert.Subject)
	policy += fmt.Sprintf("Издатель (корневой CA): %s\n", cert.Issuer)
	policy += fmt.Sprintf("Серийный номер (hex): %X\n", cert.SerialNumber)
	policy += "Срок действия:\n"
	policy += fmt.Sprintf("  Начало: %s\n", cert.NotBefore.Format(time.RFC3339))
	policy += fmt.Sprintf("  Окончание: %s\n", cert.NotAfter.Format(time.RFC3339))

	// Получение информации об алгоритме ключа
	algo, size, _ := certs.GetKeyAlgorithm(cert.PublicKey)
	policy += fmt.Sprintf("Алгоритм ключа: %s-%d\n", algo, size)

	policy += fmt.Sprintf("Ограничение длины пути: %d\n", cfg.PathLen)
	policy += fmt.Sprintf("Алгоритм подписи: %s\n", cert.SignatureAlgorithm)

	return os.WriteFile(policyPath, []byte(policy), 0644)
}
