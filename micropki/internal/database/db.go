// Package database предоставляет функциональность для работы с базой данных SQLite,
// хранения и управления сертификатами X.509.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// CertificateRecord представляет запись сертификата в базе данных.
type CertificateRecord struct {
	ID               int
	SerialHex        string
	Subject          string
	Issuer           string
	NotBefore        time.Time
	NotAfter         time.Time
	CertPEM          string
	Status           string // 'valid', 'revoked', 'expired'
	RevocationReason sql.NullString
	RevocationDate   sql.NullTime
	CreatedAt        time.Time
}

// DB представляет подключение к базе данных SQLite.
type DB struct {
	*sql.DB
	path string
}

// New создает новое подключение к базе данных SQLite.
// Если база данных не существует, она будет создана при вызове InitSchema.
func New(dbPath string) (*DB, error) {
	// Убеждаемся, что директория для базы данных существует
	dbDir := filepath.Dir(dbPath)
	if dbDir != "." && dbDir != "" {
		if err := os.MkdirAll(dbDir, 0700); err != nil {
			return nil, fmt.Errorf("не удалось создать директорию для БД: %w", err)
		}
	}

	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть базу данных: %w", err)
	}

	// Проверяем подключение
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
	}

	return &DB{DB: db, path: dbPath}, nil
}

// InitSchema создает схему базы данных, если она еще не существует.
// Функция идемпотентна - может вызываться без ошибок.
func (db *DB) InitSchema() error {
	// Проверяем, существует ли уже таблица
	var tableName string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'`).Scan(&tableName)
	if err == nil {
		// Таблица уже существует - ничего не делаем
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("ошибка при проверке существования таблицы: %w", err)
	}

	// Создаем таблицу сертификатов
	createTableSQL := `
	CREATE TABLE certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		serial_hex TEXT UNIQUE NOT NULL,
		subject TEXT NOT NULL,
		issuer TEXT NOT NULL,
		not_before TEXT NOT NULL,
		not_after TEXT NOT NULL,
		cert_pem TEXT NOT NULL,
		status TEXT NOT NULL,
		revocation_reason TEXT,
		revocation_date TEXT,
		created_at TEXT NOT NULL
	);
	
	CREATE INDEX idx_serial_hex ON certificates(serial_hex);
	CREATE INDEX idx_status ON certificates(status);
	CREATE INDEX idx_not_after ON certificates(not_after);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("не удалось создать таблицу certificates: %w", err)
	}

	return nil
}

// InsertCertificate вставляет новую запись сертификата в базу данных.
// Возвращает ошибку, если сертификат с таким серийным номером уже существует.
func (db *DB) InsertCertificate(record *CertificateRecord) error {
	// Конвертируем время в ISO 8601 строку
	notBefore := record.NotBefore.UTC().Format(time.RFC3339)
	notAfter := record.NotAfter.UTC().Format(time.RFC3339)
	createdAt := time.Now().UTC().Format(time.RFC3339)

	// Убеждаемся, что статус установлен
	status := record.Status
	if status == "" {
		status = "valid"
	}

	// Вставляем запись
	insertSQL := `
	INSERT INTO certificates (
		serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.Exec(insertSQL,
		record.SerialHex,
		record.Subject,
		record.Issuer,
		notBefore,
		notAfter,
		record.CertPEM,
		status,
		createdAt,
	)

	if err != nil {
		return fmt.Errorf("не удалось вставить сертификат: %w", err)
	}

	return nil
}

// GetCertificateBySerial извлекает сертификат по серийному номеру (hex).
func (db *DB) GetCertificateBySerial(serialHex string) (*CertificateRecord, error) {
	querySQL := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, 
	       status, revocation_reason, revocation_date, created_at
	FROM certificates
	WHERE serial_hex = ?
	`

	record := &CertificateRecord{}
	var notBeforeStr, notAfterStr, createdAtStr string
	var revocationReason sql.NullString
	var revocationDate sql.NullString

	err := db.QueryRow(querySQL, serialHex).Scan(
		&record.ID,
		&record.SerialHex,
		&record.Subject,
		&record.Issuer,
		&notBeforeStr,
		&notAfterStr,
		&record.CertPEM,
		&record.Status,
		&revocationReason,
		&revocationDate,
		&createdAtStr,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении сертификата: %w", err)
	}

	// Парсим временные метки
	record.NotBefore, err = time.Parse(time.RFC3339, notBeforeStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить not_before: %w", err)
	}
	record.NotAfter, err = time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить not_after: %w", err)
	}
	record.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить created_at: %w", err)
	}

	// Обрабатываем NULL поля
	if revocationReason.Valid {
		record.RevocationReason = revocationReason
	}
	if revocationDate.Valid {
		var revDate time.Time
		revDate, err = time.Parse(time.RFC3339, revocationDate.String)
		if err != nil {
			return nil, fmt.Errorf("не удалось распарсить revocation_date: %w", err)
		}
		record.RevocationDate = sql.NullTime{Time: revDate, Valid: true}
	}

	return record, nil
}

// ListCertificates возвращает список сертификатов с возможностью фильтрации.
func (db *DB) ListCertificates(status string, issuer string) ([]*CertificateRecord, error) {
	querySQL := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at
	FROM certificates
	WHERE 1=1
	`
	args := []interface{}{}

	if status != "" {
		querySQL += " AND status = ?"
		args = append(args, status)
	}
	if issuer != "" {
		querySQL += " AND issuer LIKE ?"
		args = append(args, "%"+issuer+"%")
	}

	querySQL += " ORDER BY created_at DESC"

	rows, err := db.Query(querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("ошибка при запросе списка сертификатов: %w", err)
	}
	defer rows.Close()

	var records []*CertificateRecord
	for rows.Next() {
		record := &CertificateRecord{}
		var notBeforeStr, notAfterStr, createdAtStr string

		err := rows.Scan(
			&record.ID,
			&record.SerialHex,
			&record.Subject,
			&record.Issuer,
			&notBeforeStr,
			&notAfterStr,
			&record.CertPEM,
			&record.Status,
			&createdAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("ошибка при сканировании строки: %w", err)
		}

		record.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
		record.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
		record.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		records = append(records, record)
	}

	return records, nil
}

// UpdateCertificateStatus обновляет статус сертификата.
// Для отзыва также устанавливает причину и дату отзыва.
func (db *DB) UpdateCertificateStatus(serialHex string, status string, reason string) error {
	var err error

	if status == "revoked" && reason != "" {
		// Отзыв сертификата
		revocationDate := time.Now().UTC().Format(time.RFC3339)
		updateSQL := `
		UPDATE certificates 
		SET status = ?, revocation_reason = ?, revocation_date = ?
		WHERE serial_hex = ?
		`
		_, err = db.Exec(updateSQL, status, reason, revocationDate, serialHex)
	} else {
		// Простое обновление статуса
		updateSQL := `
		UPDATE certificates 
		SET status = ?
		WHERE serial_hex = ?
		`
		_, err = db.Exec(updateSQL, status, serialHex)
	}

	if err != nil {
		return fmt.Errorf("не удалось обновить статус сертификата: %w", err)
	}

	return nil
}

// GetRevokedCertificates возвращает все отозванные сертификаты (для CRL).
func (db *DB) GetRevokedCertificates() ([]*CertificateRecord, error) {
	querySQL := `
	SELECT serial_hex, revocation_reason, revocation_date
	FROM certificates
	WHERE status = 'revoked'
	ORDER BY revocation_date DESC
	`

	rows, err := db.Query(querySQL)
	if err != nil {
		return nil, fmt.Errorf("ошибка при запросе отозванных сертификатов: %w", err)
	}
	defer rows.Close()

	var records []*CertificateRecord
	for rows.Next() {
		record := &CertificateRecord{}
		var revocationDateStr string

		err := rows.Scan(
			&record.SerialHex,
			&record.RevocationReason,
			&revocationDateStr,
		)
		if err != nil {
			return nil, fmt.Errorf("ошибка при сканировании строки: %w", err)
		}

		revDate, _ := time.Parse(time.RFC3339, revocationDateStr)
		record.RevocationDate = sql.NullTime{Time: revDate, Valid: true}

		records = append(records, record)
	}

	return records, nil
}

// Close закрывает подключение к базе данных.
func (db *DB) Close() error {
	return db.DB.Close()
}

// Path возвращает путь к файлу базы данных.
func (db *DB) Path() string {
	return db.path
}
