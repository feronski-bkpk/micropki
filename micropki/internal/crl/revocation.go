package crl

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RevocationManager управляет процессом отзыва сертификатов.
type RevocationManager struct {
	db     *sql.DB
	crlDir string
}

// NewRevocationManager создает новый менеджер отзыва.
func NewRevocationManager(db *sql.DB, crlDir string) *RevocationManager {
	return &RevocationManager{
		db:     db,
		crlDir: crlDir,
	}
}

// normalizeSerial приводит серийный номер к стандартному виду (без ведущих нулей, нижний регистр, чётная длина)
func normalizeSerial(serialHex string) string {
	normalized := strings.TrimLeft(serialHex, "0")
	if normalized == "" {
		normalized = "0"
	}
	normalized = strings.ToLower(normalized)

	if len(normalized)%2 != 0 {
		normalized = "0" + normalized
	}

	return normalized
}

// RevokeCertificate отзывает сертификат по серийному номеру.
func (m *RevocationManager) RevokeCertificate(serialHex string, reasonCode ReasonCode) error {
	workingSerial := serialHex
	if len(workingSerial)%2 != 0 {
		workingSerial = "0" + workingSerial
	}

	_, err := hex.DecodeString(workingSerial)
	if err != nil {
		return fmt.Errorf("неверный формат серийного номера (ожидается hex): %w, строка: %s", err, serialHex)
	}

	normalizedSerial := normalizeSerial(workingSerial)

	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("не удалось начать транзакцию: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT serial_hex FROM certificates")
	if err != nil {
		return fmt.Errorf("ошибка при поиске сертификата: %w", err)
	}
	defer rows.Close()

	var foundSerial string
	var found bool
	for rows.Next() {
		var dbSerial string
		if err := rows.Scan(&dbSerial); err != nil {
			continue
		}
		if normalizeSerial(dbSerial) == normalizedSerial {
			foundSerial = dbSerial
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	var status string
	var currentReason sql.NullString
	err = tx.QueryRow(
		"SELECT status, revocation_reason FROM certificates WHERE serial_hex = ?",
		foundSerial,
	).Scan(&status, &currentReason)

	if err != nil {
		return fmt.Errorf("ошибка при проверке статуса: %w", err)
	}

	if status == "revoked" {
		return fmt.Errorf("сертификат %s уже отозван (причина: %s)",
			serialHex, currentReason.String)
	}

	revocationTime := time.Now().UTC()
	_, err = tx.Exec(
		`UPDATE certificates 
         SET status = 'revoked', 
             revocation_reason = ?, 
             revocation_date = ? 
         WHERE serial_hex = ?`,
		reasonCode.String(),
		revocationTime.Format(time.RFC3339),
		foundSerial,
	)
	if err != nil {
		return fmt.Errorf("не удалось обновить статус сертификата: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}

	return nil
}

// CheckRevoked проверяет, отозван ли сертификат.
// Возвращает true и причину, если отозван.
func (m *RevocationManager) CheckRevoked(serialHex string) (bool, *ReasonCode, error) {
	workingSerial := serialHex
	if len(workingSerial)%2 != 0 {
		workingSerial = "0" + workingSerial
	}

	normalizedSerial := normalizeSerial(workingSerial)

	rows, err := m.db.Query("SELECT serial_hex, status, revocation_reason FROM certificates")
	if err != nil {
		return false, nil, fmt.Errorf("ошибка при поиске сертификата: %w", err)
	}
	defer rows.Close()

	var status string
	var reasonStr sql.NullString
	var found bool

	for rows.Next() {
		var dbSerial string
		var dbStatus string
		var dbReason sql.NullString
		if err := rows.Scan(&dbSerial, &dbStatus, &dbReason); err != nil {
			continue
		}
		if normalizeSerial(dbSerial) == normalizedSerial {
			status = dbStatus
			reasonStr = dbReason
			found = true
			break
		}
	}

	if !found {
		return false, nil, fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
	}

	if status != "revoked" {
		return false, nil, nil
	}

	if reasonStr.Valid && reasonStr.String != "" {
		reason, err := ParseReasonCode(reasonStr.String)
		if err == nil {
			return true, &reason, nil
		}
	}

	return true, nil, nil
}

// GetIssuerForCertificate возвращает DN издателя для сертификата.
func (m *RevocationManager) GetIssuerForCertificate(serialHex string) (string, error) {
	workingSerial := serialHex
	if len(workingSerial)%2 != 0 {
		workingSerial = "0" + workingSerial
	}

	normalizedSerial := normalizeSerial(workingSerial)

	rows, err := m.db.Query("SELECT serial_hex, issuer FROM certificates")
	if err != nil {
		return "", fmt.Errorf("ошибка при поиске сертификата: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dbSerial string
		var issuer string
		if err := rows.Scan(&dbSerial, &issuer); err != nil {
			continue
		}
		if normalizeSerial(dbSerial) == normalizedSerial {
			return issuer, nil
		}
	}

	return "", fmt.Errorf("сертификат с серийным номером %s не найден", serialHex)
}

// GetRevokedCertificates возвращает список всех отозванных сертификатов для указанного CA.
func (m *RevocationManager) GetRevokedCertificates(issuerDN string) ([]RevokedCertificate, error) {
	rows, err := m.db.Query(
		`SELECT serial_hex, revocation_reason, revocation_date 
         FROM certificates 
         WHERE status = 'revoked' AND issuer = ? 
         ORDER BY revocation_date DESC`,
		issuerDN,
	)
	if err != nil {
		return nil, fmt.Errorf("ошибка при запросе отозванных сертификатов: %w", err)
	}
	defer rows.Close()

	var revoked []RevokedCertificate
	for rows.Next() {
		var (
			serialHex      string
			reasonStr      sql.NullString
			revocationDate sql.NullString
		)

		if err := rows.Scan(&serialHex, &reasonStr, &revocationDate); err != nil {
			return nil, fmt.Errorf("ошибка при сканировании строки: %w", err)
		}

		serialBytes, err := hex.DecodeString(serialHex)
		if err != nil {
			continue
		}
		serial := new(big.Int).SetBytes(serialBytes)

		revTime := time.Now().UTC()
		if revocationDate.Valid {
			revTime, _ = time.Parse(time.RFC3339, revocationDate.String)
		}

		rc := RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: revTime,
		}

		if reasonStr.Valid && reasonStr.String != "" {
			reason, err := ParseReasonCode(reasonStr.String)
			if err == nil {
				rc.ReasonCode = &reason
			}
		}

		revoked = append(revoked, rc)
	}

	return revoked, nil
}
