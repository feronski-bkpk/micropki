// Package compromise предоставляет функциональность для работы с компрометированными ключами
package compromise

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"micropki/micropki/internal/database"
)

// CompromiseManager управляет компрометированными ключами
type CompromiseManager struct {
	db     *database.DB
	logger *log.Logger
}

// NewCompromiseManager создает новый менеджер компрометации
func NewCompromiseManager(db *database.DB, logger *log.Logger) *CompromiseManager {
	return &CompromiseManager{
		db:     db,
		logger: logger,
	}
}

// MarkKeyCompromised отмечает ключ как скомпрометированный
func (c *CompromiseManager) MarkKeyCompromised(cert *x509.Certificate, reason string) error {
	publicKeyHash, err := c.computePublicKeyHash(cert)
	if err != nil {
		return fmt.Errorf("не удалось вычислить хеш ключа: %w", err)
	}

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())

	query := `
	INSERT OR REPLACE INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason)
	VALUES (?, ?, ?, ?)
	`

	_, err = c.db.Exec(query, publicKeyHash, serialHex, time.Now().UTC().Format(time.RFC3339), reason)
	if err != nil {
		return fmt.Errorf("не удалось сохранить запись о компрометации: %w", err)
	}

	if c.logger != nil {
		c.logger.Printf("Ключ помечен как скомпрометированный: сертификат %s, причина %s", serialHex, reason)
	}

	return nil
}

// IsKeyCompromised проверяет, скомпрометирован ли ключ
func (c *CompromiseManager) IsKeyCompromised(cert *x509.Certificate) (bool, error) {
	publicKeyHash, err := c.computePublicKeyHash(cert)
	if err != nil {
		return false, fmt.Errorf("не удалось вычислить хеш ключа: %w", err)
	}

	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM compromised_keys WHERE public_key_hash = ?", publicKeyHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке ключа: %w", err)
	}

	return count > 0, nil
}

// computePublicKeyHash вычисляет SHA-256 хеш открытого ключа в DER формате
func (c *CompromiseManager) computePublicKeyHash(cert *x509.Certificate) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("не удалось маршалировать открытый ключ: %w", err)
	}

	hash := sha256.Sum256(publicKeyDER)
	return hex.EncodeToString(hash[:]), nil
}

// CheckCSRForCompromisedKey проверяет, не скомпрометирован ли ключ в CSR
func (c *CompromiseManager) CheckCSRForCompromisedKey(csrPEM []byte) (bool, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return false, fmt.Errorf("не удалось декодировать CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("не удалось разобрать CSR: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return false, fmt.Errorf("не удалось маршалировать открытый ключ: %w", err)
	}

	hash := sha256.Sum256(publicKeyDER)
	publicKeyHash := hex.EncodeToString(hash[:])

	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM compromised_keys WHERE public_key_hash = ?", publicKeyHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке ключа: %w", err)
	}

	return count > 0, nil
}

// IsKeyCompromisedByPublicKey проверяет, скомпрометирован ли ключ по публичному ключу
func (c *CompromiseManager) IsKeyCompromisedByPublicKey(publicKey crypto.PublicKey) (bool, error) {
	publicKeyHash, err := computePublicKeyHashFromPublicKey(publicKey)
	if err != nil {
		return false, fmt.Errorf("не удалось вычислить хеш ключа: %w", err)
	}

	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM compromised_keys WHERE public_key_hash = ?", publicKeyHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке ключа: %w", err)
	}

	return count > 0, nil
}

// computePublicKeyHashFromPublicKey вычисляет SHA-256 хеш открытого ключа в DER формате
func computePublicKeyHashFromPublicKey(publicKey crypto.PublicKey) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("не удалось маршалировать открытый ключ: %w", err)
	}

	hash := sha256.Sum256(publicKeyDER)
	return hex.EncodeToString(hash[:]), nil
}
