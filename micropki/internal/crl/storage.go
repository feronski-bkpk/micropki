package crl

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CRLStorage предоставляет методы для хранения и загрузки CRL метаданных.
type CRLStorage struct {
	db *sql.DB
}

// NewCRLStorage создает новый экземпляр хранилища CRL.
func NewCRLStorage(db *sql.DB) *CRLStorage {
	return &CRLStorage{db: db}
}

// InitCRLTable создает таблицу для хранения метаданных CRL.
func (s *CRLStorage) InitCRLTable() error {
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
	
	CREATE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject);
	`

	_, err := s.db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("не удалось создать таблицу crl_metadata: %w", err)
	}

	return nil
}

// GetCRLNumber возвращает текущий номер CRL для указанного CA.
func (s *CRLStorage) GetCRLNumber(caSubject string) (int, error) {
	var crlNumber int
	err := s.db.QueryRow(
		"SELECT crl_number FROM crl_metadata WHERE ca_subject = ?",
		caSubject,
	).Scan(&crlNumber)

	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("ошибка при получении номера CRL: %w", err)
	}

	return crlNumber, nil
}

// IncrementCRLNumber увеличивает номер CRL для указанного CA.
func (s *CRLStorage) IncrementCRLNumber(caSubject string) (int, error) {
	current, err := s.GetCRLNumber(caSubject)
	if err != nil {
		return 0, err
	}

	newNumber := current + 1
	now := time.Now().UTC().Format(time.RFC3339)

	result, err := s.db.Exec(
		`UPDATE crl_metadata 
		 SET crl_number = ?, updated_at = ? 
		 WHERE ca_subject = ?`,
		newNumber, now, caSubject,
	)
	if err != nil {
		return 0, fmt.Errorf("ошибка при обновлении номера CRL: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		_, err = s.db.Exec(
			`INSERT INTO crl_metadata 
			 (ca_subject, crl_number, last_generated, this_update, next_update, crl_path, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caSubject, newNumber, now, now, now, "", now, now,
		)
		if err != nil {
			return 0, fmt.Errorf("ошибка при вставке номера CRL: %w", err)
		}
	}

	return newNumber, nil
}

// UpdateCRLInfo обновляет информацию о сгенерированном CRL.
func (s *CRLStorage) UpdateCRLInfo(info *CRLInfo) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM crl_metadata WHERE ca_subject = ?",
		info.CASubject,
	).Scan(&count)

	if err != nil {
		return fmt.Errorf("ошибка при проверке существования записи: %w", err)
	}

	if count == 0 {
		_, err = s.db.Exec(
			`INSERT INTO crl_metadata 
			 (ca_subject, crl_number, last_generated, this_update, next_update, 
			  crl_path, revoked_count, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			info.CASubject,
			info.CRLNumber,
			info.LastGenerated.Format(time.RFC3339),
			info.ThisUpdate.Format(time.RFC3339),
			info.NextUpdate.Format(time.RFC3339),
			info.CRLPath,
			info.RevokedCount,
			now,
			now,
		)
	} else {
		_, err = s.db.Exec(
			`UPDATE crl_metadata 
			 SET crl_number = ?, last_generated = ?, this_update = ?, next_update = ?,
			     crl_path = ?, revoked_count = ?, updated_at = ?
			 WHERE ca_subject = ?`,
			info.CRLNumber,
			info.LastGenerated.Format(time.RFC3339),
			info.ThisUpdate.Format(time.RFC3339),
			info.NextUpdate.Format(time.RFC3339),
			info.CRLPath,
			info.RevokedCount,
			now,
			info.CASubject,
		)
	}

	if err != nil {
		return fmt.Errorf("не удалось обновить метаданные CRL: %w", err)
	}

	return nil
}

// GetCRLInfo возвращает информацию о последнем CRL для указанного CA.
func (s *CRLStorage) GetCRLInfo(caSubject string) (*CRLInfo, error) {
	var (
		lastGeneratedStr, thisUpdateStr, nextUpdateStr, createdAtStr, updatedAtStr string
		info                                                                       = &CRLInfo{CASubject: caSubject}
	)

	err := s.db.QueryRow(
		`SELECT crl_number, last_generated, this_update, next_update, crl_path, revoked_count,
		        created_at, updated_at
		 FROM crl_metadata 
		 WHERE ca_subject = ?`,
		caSubject,
	).Scan(
		&info.CRLNumber,
		&lastGeneratedStr,
		&thisUpdateStr,
		&nextUpdateStr,
		&info.CRLPath,
		&info.RevokedCount,
		&createdAtStr,
		&updatedAtStr,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении информации CRL: %w", err)
	}

	info.LastGenerated, _ = time.Parse(time.RFC3339, lastGeneratedStr)
	info.ThisUpdate, _ = time.Parse(time.RFC3339, thisUpdateStr)
	info.NextUpdate, _ = time.Parse(time.RFC3339, nextUpdateStr)

	return info, nil
}

// SaveCRLToFile сохраняет CRL в PEM-файл.
func SaveCRLToFile(crlPEM string, outDir, caName string) (string, error) {
	crlDir := filepath.Join(outDir, "crl")
	if err := os.MkdirAll(crlDir, 0755); err != nil {
		return "", fmt.Errorf("не удалось создать директорию crl: %w", err)
	}

	filename := filepath.Join(crlDir, caName+".crl.pem")

	if err := os.WriteFile(filename, []byte(crlPEM), 0644); err != nil {
		return "", fmt.Errorf("не удалось сохранить CRL: %w", err)
	}

	return filename, nil
}

// LoadCRLFromFile загружает CRL из PEM-файла.
func LoadCRLFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать CRL файл: %w", err)
	}
	return string(data), nil
}
