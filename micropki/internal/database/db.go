// Package database предоставляет функциональность для работы с базой данных SQLite,
// хранения и управления сертификатами X.509.
package database

import (
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/ocsp"
	"os"
	"path/filepath"
	"strings"
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
	Status           string
	RevocationReason sql.NullString
	RevocationDate   sql.NullTime
	CreatedAt        time.Time
}

// CRLMetadata представляет метаданные CRL в базе данных.
type CRLMetadata struct {
	ID            int
	CASubject     string
	CRLNumber     int
	LastGenerated time.Time
	ThisUpdate    time.Time
	NextUpdate    time.Time
	CRLPath       string
	RevokedCount  int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DB представляет подключение к базе данных SQLite.
type DB struct {
	*sql.DB
	path string
}

// New создает новое подключение к базе данных SQLite.
// Если база данных не существует, она будет создана при вызове InitSchema.
func New(dbPath string) (*DB, error) {
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

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
	}

	return &DB{DB: db, path: dbPath}, nil
}

// InitSchema создает схему базы данных, если она еще не существует.
func (db *DB) InitSchema() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS certificates (
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
	
	CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
	CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
	CREATE INDEX IF NOT EXISTS idx_issuer ON certificates(issuer);
	CREATE INDEX IF NOT EXISTS idx_not_after ON certificates(not_after);
	`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("не удалось создать таблицу certificates: %w", err)
	}

	return nil
}

// InitCRLSchema создает таблицы для CRL, если они не существуют.
func (db *DB) InitCRLSchema() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS crl_metadata (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ca_subject TEXT NOT NULL UNIQUE,
		crl_number INTEGER NOT NULL,
		last_generated TEXT NOT NULL,
		this_update TEXT NOT NULL,
		next_update TEXT NOT NULL,
		crl_path TEXT NOT NULL,
		revoked_count INTEGER DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	
	CREATE INDEX IF NOT EXISTS idx_crl_ca_subject ON crl_metadata(ca_subject);
	`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("не удалось создать таблицу crl_metadata: %w", err)
	}

	return nil
}

// InitSchemaWithCRL инициализирует схему базы данных, включая CRL таблицы.
func (db *DB) InitSchemaWithCRL() error {
	if err := db.InitSchema(); err != nil {
		return err
	}

	if err := db.InitCRLSchema(); err != nil {
		return err
	}

	return nil
}

// InsertCertificate вставляет новую запись сертификата в базу данных.
// Возвращает ошибку, если сертификат с таким серийным номером уже существует.
func (db *DB) InsertCertificate(record *CertificateRecord) error {
	notBefore := record.NotBefore.UTC().Format(time.RFC3339)
	notAfter := record.NotAfter.UTC().Format(time.RFC3339)
	createdAt := time.Now().UTC().Format(time.RFC3339)

	status := record.Status
	if status == "" {
		status = "valid"
	}

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
		revocationDate := time.Now().UTC().Format(time.RFC3339)
		updateSQL := `
		UPDATE certificates 
		SET status = ?, revocation_reason = ?, revocation_date = ?
		WHERE serial_hex = ?
		`
		_, err = db.Exec(updateSQL, status, reason, revocationDate, serialHex)
	} else {
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

// GetRevokedCertificatesForIssuer возвращает все отозванные сертификаты для указанного издателя.
func (db *DB) GetRevokedCertificatesForIssuer(issuer string) ([]*CertificateRecord, error) {
	querySQL := `
    SELECT serial_hex, revocation_reason, revocation_date
    FROM certificates
    WHERE status = 'revoked' AND issuer = ?
    ORDER BY revocation_date DESC
    `

	rows, err := db.Query(querySQL, issuer)
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

		record.SerialHex = strings.ToUpper(record.SerialHex)

		if revocationDateStr != "" {
			revDate, err := time.Parse(time.RFC3339, revocationDateStr)
			if err != nil {
				record.RevocationDate = sql.NullTime{Time: time.Now().UTC(), Valid: true}
			} else {
				record.RevocationDate = sql.NullTime{Time: revDate, Valid: true}
			}
		} else {
			record.RevocationDate = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		}

		records = append(records, record)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка при итерации по строкам: %w", err)
	}

	return records, nil
}

// UpdateCRLMetadata обновляет метаданные CRL для указанного CA.
func (db *DB) UpdateCRLMetadata(metadata *CRLMetadata) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM crl_metadata WHERE ca_subject = ?",
		metadata.CASubject,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("ошибка при проверке существования метаданных: %w", err)
	}

	if count == 0 {
		_, err = db.Exec(
			`INSERT INTO crl_metadata 
			 (ca_subject, crl_number, last_generated, this_update, next_update, 
			  crl_path, revoked_count, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			metadata.CASubject,
			metadata.CRLNumber,
			metadata.LastGenerated.Format(time.RFC3339),
			metadata.ThisUpdate.Format(time.RFC3339),
			metadata.NextUpdate.Format(time.RFC3339),
			metadata.CRLPath,
			metadata.RevokedCount,
			now,
			now,
		)
	} else {
		_, err = db.Exec(
			`UPDATE crl_metadata 
			 SET crl_number = ?, last_generated = ?, this_update = ?, next_update = ?,
			     crl_path = ?, revoked_count = ?, updated_at = ?
			 WHERE ca_subject = ?`,
			metadata.CRLNumber,
			metadata.LastGenerated.Format(time.RFC3339),
			metadata.ThisUpdate.Format(time.RFC3339),
			metadata.NextUpdate.Format(time.RFC3339),
			metadata.CRLPath,
			metadata.RevokedCount,
			now,
			metadata.CASubject,
		)
	}

	if err != nil {
		return fmt.Errorf("не удалось обновить метаданные CRL: %w", err)
	}

	return nil
}

// GetCRLMetadata возвращает метаданные CRL для указанного CA.
func (db *DB) GetCRLMetadata(caSubject string) (*CRLMetadata, error) {
	var (
		lastGeneratedStr, thisUpdateStr, nextUpdateStr, createdAtStr, updatedAtStr string
		metadata                                                                   = &CRLMetadata{CASubject: caSubject}
	)

	err := db.QueryRow(
		`SELECT id, crl_number, last_generated, this_update, next_update, 
		        crl_path, revoked_count, created_at, updated_at
		 FROM crl_metadata 
		 WHERE ca_subject = ?`,
		caSubject,
	).Scan(
		&metadata.ID,
		&metadata.CRLNumber,
		&lastGeneratedStr,
		&thisUpdateStr,
		&nextUpdateStr,
		&metadata.CRLPath,
		&metadata.RevokedCount,
		&createdAtStr,
		&updatedAtStr,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении метаданных CRL: %w", err)
	}

	metadata.LastGenerated, _ = time.Parse(time.RFC3339, lastGeneratedStr)
	metadata.ThisUpdate, _ = time.Parse(time.RFC3339, thisUpdateStr)
	metadata.NextUpdate, _ = time.Parse(time.RFC3339, nextUpdateStr)
	metadata.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	metadata.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)

	return metadata, nil
}

// Close закрывает подключение к базе данных.
func (db *DB) Close() error {
	return db.DB.Close()
}

// Path возвращает путь к файлу базы данных.
func (db *DB) Path() string {
	return db.path
}

// GetCertificateStatusForOCSP возвращает статус сертификата для OCSP
func (db *DB) GetCertificateStatusForOCSP(issuerNameHash, issuerKeyHash []byte, serial *big.Int) (*ocsp.StatusResult, error) {
	serialHex := hex.EncodeToString(serial.Bytes())

	var status string
	var revocationReason sql.NullString
	var revocationDate sql.NullString
	var issuer string

	err := db.QueryRow(
		`SELECT status, revocation_reason, revocation_date, issuer 
		 FROM certificates 
		 WHERE serial_hex = ?`,
		serialHex,
	).Scan(&status, &revocationReason, &revocationDate, &issuer)

	if err == sql.ErrNoRows {
		return &ocsp.StatusResult{
			Status:     ocsp.StatusUnknown,
			ThisUpdate: time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка при запросе статуса: %w", err)
	}

	switch status {
	case "valid":
		return &ocsp.StatusResult{
			Status:     ocsp.StatusGood,
			ThisUpdate: time.Now().UTC(),
		}, nil

	case "revoked":
		var revTime time.Time
		if revocationDate.Valid {
			revTime, _ = time.Parse(time.RFC3339, revocationDate.String)
		} else {
			revTime = time.Now().UTC()
		}

		var reason *int
		if revocationReason.Valid && revocationReason.String != "" {
		}

		return &ocsp.StatusResult{
			Status:           ocsp.StatusRevoked,
			RevocationTime:   &revTime,
			RevocationReason: reason,
			ThisUpdate:       time.Now().UTC(),
		}, nil

	default:
		return &ocsp.StatusResult{
			Status:     ocsp.StatusUnknown,
			ThisUpdate: time.Now().UTC(),
		}, nil
	}
}

// GetIssuerByHashes возвращает сертификат издателя по хешам
func (db *DB) GetIssuerByHashes(nameHash, keyHash []byte) (*x509.Certificate, error) {
	intPath := filepath.Join(filepath.Dir(db.path), "intermediate", "certs", "intermediate.cert.pem")
	if cert, err := certs.LoadCertificate(intPath); err == nil {
		if match, _ := ocsp.VerifyCertID(&ocsp.CertID{
			IssuerNameHash: nameHash,
			IssuerKeyHash:  keyHash,
		}, cert); match {
			return cert, nil
		}
	}

	rootPath := filepath.Join(filepath.Dir(db.path), "root", "certs", "ca.cert.pem")
	if cert, err := certs.LoadCertificate(rootPath); err == nil {
		if match, _ := ocsp.VerifyCertID(&ocsp.CertID{
			IssuerNameHash: nameHash,
			IssuerKeyHash:  keyHash,
		}, cert); match {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("издатель не найден")
}

// DatabaseStatusChecker реализует интерфейс ocsp.StatusChecker
type DatabaseStatusChecker struct {
	db *DB
}

// NewDatabaseStatusChecker создаёт новый проверяльщик статуса
func (db *DB) NewDatabaseStatusChecker() *DatabaseStatusChecker {
	return &DatabaseStatusChecker{db: db}
}

// GetCertificateStatus реализует интерфейс ocsp.StatusChecker
func (c *DatabaseStatusChecker) GetCertificateStatus(issuerNameHash, issuerKeyHash []byte, serial *big.Int) (*ocsp.StatusResult, error) {
	return c.db.GetCertificateStatusForOCSP(issuerNameHash, issuerKeyHash, serial)
}

// GetIssuerByHashes реализует интерфейс ocsp.StatusChecker
func (c *DatabaseStatusChecker) GetIssuerByHashes(nameHash, keyHash []byte) (*x509.Certificate, error) {
	return c.db.GetIssuerByHashes(nameHash, keyHash)
}
