package crl

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupRevocationTestDB создает БД с таблицей certificates для тестов отзыва
func setupRevocationTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	db, cleanup := setupTestDB(t)

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
		);`

	_, err := db.Exec(createTableSQL)
	if err != nil {
		t.Fatalf("Failed to create certificates table: %v", err)
	}

	return db, cleanup
}

// TestRevokeCertificate проверяет отзыв сертификата
func TestRevokeCertificate(t *testing.T) {
	db, cleanup := setupRevocationTestDB(t)
	defer cleanup()

	revokeMgr := NewRevocationManager(db, os.TempDir())

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`INSERT INTO certificates
		(serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"1234567890abcdef",
		"CN=test.example.com",
		"CN=Test CA",
		now,
		now,
		"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----",
		"valid",
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert test certificate: %v", err)
	}

	err = revokeMgr.RevokeCertificate("1234567890abcdef", ReasonKeyCompromise)
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	var status, reason string
	err = db.QueryRow(
		"SELECT status, COALESCE(revocation_reason, '') FROM certificates WHERE serial_hex = ?",
		"1234567890abcdef",
	).Scan(&status, &reason)

	if err != nil {
		t.Fatalf("Failed to query certificate: %v", err)
	}

	if status != "revoked" {
		t.Errorf("Status = %s, want revoked", status)
	}
	if reason != "keyCompromise" {
		t.Errorf("Reason = %s, want keyCompromise", reason)
	}
}

// TestCheckRevoked проверяет функцию проверки статуса
func TestCheckRevoked(t *testing.T) {
	db, cleanup := setupRevocationTestDB(t)
	defer cleanup()

	revokeMgr := NewRevocationManager(db, os.TempDir())

	now := time.Now().UTC().Format(time.RFC3339)

	_, err := db.Exec(
		`INSERT INTO certificates
		(serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"1111111111111111",
		"CN=valid.example.com",
		"CN=Test CA",
		now,
		now,
		"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----",
		"valid",
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert valid certificate: %v", err)
	}

	_, err = db.Exec(
		`INSERT INTO certificates
		(serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"2222222222222222",
		"CN=revoked.example.com",
		"CN=Test CA",
		now,
		now,
		"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----",
		"revoked",
		"keyCompromise",
		now,
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert revoked certificate: %v", err)
	}

	revoked, reason, err := revokeMgr.CheckRevoked("1111111111111111")
	if err != nil {
		t.Fatalf("CheckRevoked failed for valid cert: %v", err)
	}
	if revoked {
		t.Error("Valid certificate reported as revoked")
	}
	if reason != nil {
		t.Errorf("Valid certificate has reason: %v", reason)
	}

	revoked, reason, err = revokeMgr.CheckRevoked("2222222222222222")
	if err != nil {
		t.Fatalf("CheckRevoked failed for revoked cert: %v", err)
	}
	if !revoked {
		t.Error("Revoked certificate reported as valid")
	}
	if reason == nil || *reason != ReasonKeyCompromise {
		t.Errorf("Wrong reason: %v, want keyCompromise", reason)
	}

	_, _, err = revokeMgr.CheckRevoked("9999999999999999")
	if err == nil {
		t.Error("CheckRevoked for non-existent cert should return error")
	}
}

// TestGetIssuerForCertificate проверяет получение издателя
func TestGetIssuerForCertificate(t *testing.T) {
	db, cleanup := setupRevocationTestDB(t)
	defer cleanup()

	revokeMgr := NewRevocationManager(db, os.TempDir())

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`INSERT INTO certificates
		(serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"1234567890abcdef",
		"CN=test.example.com",
		"CN=Test Issuer CA",
		now,
		now,
		"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----",
		"valid",
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert test certificate: %v", err)
	}

	issuer, err := revokeMgr.GetIssuerForCertificate("1234567890abcdef")
	if err != nil {
		t.Fatalf("GetIssuerForCertificate failed: %v", err)
	}

	if issuer != "CN=Test Issuer CA" {
		t.Errorf("Issuer = %s, want CN=Test Issuer CA", issuer)
	}

	_, err = revokeMgr.GetIssuerForCertificate("9999999999999999")
	if err == nil {
		t.Error("GetIssuerForCertificate for non-existent cert should return error")
	}
}
