// Package ca реализует операции центра сертификации (Certificate Authority).
// Пакет предоставляет функциональность для создания и управления корневыми
// и промежуточными центрами сертификации, а также для выпуска конечных
// сертификатов.
//
// Основные возможности:
//   - Инициализация корневого CA
//   - Создание промежуточных CA, подписанных корневым
//   - Выпуск сертификатов конечных сущностей (серверные, клиентские, подписи кода)
//   - Подписание внешних CSR
//
// Все закрытые ключи хранятся в зашифрованном виде с использованием AES-256-GCM,
// за исключением ключей конечных сертификатов, которые по умолчанию сохраняются
// незашифрованными (с предупреждением).
package ca

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"micropki/micropki/internal/database"
)

// InsertCertificateIntoDB вставляет сертификат в базу данных.
// Эта функция вызывается из команд выпуска сертификатов.
func InsertCertificateIntoDB(dbPath string, cert *x509.Certificate, certPEM []byte, logger *log.Logger) error {
	// Открываем БД
	db, err := database.New(dbPath)
	if err != nil {
		return fmt.Errorf("не удалось открыть БД: %w", err)
	}
	defer db.Close()

	// Инициализируем схему (если еще не создана)
	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("не удалось инициализировать схему БД: %w", err)
	}

	// Создаем запись
	record := &database.CertificateRecord{
		SerialHex: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		CertPEM:   string(certPEM),
		Status:    "valid",
	}

	// Вставляем в БД
	if err := db.InsertCertificate(record); err != nil {
		return fmt.Errorf("не удалось вставить сертификат в БД: %w", err)
	}

	if logger != nil {
		logger.Printf("INFO: Сертификат %X добавлен в базу данных", cert.SerialNumber)
	}

	return nil
}
