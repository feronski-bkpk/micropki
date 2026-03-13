package crl

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB создает временную БД для тестов
func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	dbPath := filepath.Join(os.TempDir(), "test-"+time.Now().Format("150405")+".db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test DB: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(dbPath)
	}

	return db, cleanup
}

// TestCRLStorageInit проверяет инициализацию таблицы CRL
func TestCRLStorageInit(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	storage := NewCRLStorage(db)

	err := storage.InitCRLTable()
	if err != nil {
		t.Fatalf("InitCRLTable failed: %v", err)
	}

	var tableName string
	err = db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='crl_metadata'",
	).Scan(&tableName)

	if err != nil {
		t.Fatalf("Table crl_metadata not created: %v", err)
	}
}

// TestCRLNumber проверяет получение и увеличение номера CRL
func TestCRLNumber(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	storage := NewCRLStorage(db)
	storage.InitCRLTable()

	caSubject := "CN=Test CA"

	number, err := storage.GetCRLNumber(caSubject)
	if err != nil {
		t.Fatalf("GetCRLNumber failed: %v", err)
	}
	if number != 1 {
		t.Errorf("GetCRLNumber = %d, want 1", number)
	}

	newNumber, err := storage.IncrementCRLNumber(caSubject)
	if err != nil {
		t.Fatalf("IncrementCRLNumber failed: %v", err)
	}
	if newNumber != 2 {
		t.Errorf("IncrementCRLNumber = %d, want 2", newNumber)
	}

	number, err = storage.GetCRLNumber(caSubject)
	if err != nil {
		t.Fatalf("GetCRLNumber after increment failed: %v", err)
	}
	if number != 2 {
		t.Errorf("GetCRLNumber after increment = %d, want 2", number)
	}
}

// TestCRLInfoStorage проверяет сохранение и загрузку метаданных CRL
func TestCRLInfoStorage(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	storage := NewCRLStorage(db)
	err := storage.InitCRLTable()
	if err != nil {
		t.Fatalf("InitCRLTable failed: %v", err)
	}

	now := time.Now().UTC()
	info := &CRLInfo{
		CASubject:     "CN=Test CA",
		CRLNumber:     5,
		LastGenerated: now,
		NextUpdate:    now.AddDate(0, 0, 7),
		ThisUpdate:    now,
		CRLPath:       "/tmp/test.crl",
		RevokedCount:  10,
	}

	err = storage.UpdateCRLInfo(info)
	if err != nil {
		t.Fatalf("UpdateCRLInfo failed: %v", err)
	}

	loaded, err := storage.GetCRLInfo("CN=Test CA")
	if err != nil {
		t.Fatalf("GetCRLInfo failed: %v", err)
	}

	if loaded == nil {
		t.Fatal("GetCRLInfo returned nil")
	}

	if loaded.CASubject != info.CASubject {
		t.Errorf("CASubject = %v, want %v", loaded.CASubject, info.CASubject)
	}
	if loaded.CRLNumber != info.CRLNumber {
		t.Errorf("CRLNumber = %d, want %d", loaded.CRLNumber, info.CRLNumber)
	}
	if loaded.RevokedCount != info.RevokedCount {
		t.Errorf("RevokedCount = %d, want %d", loaded.RevokedCount, info.RevokedCount)
	}
}

// TestSaveLoadCRLFile проверяет сохранение и загрузку CRL файла
func TestSaveLoadCRLFile(t *testing.T) {
	tmpDir := t.TempDir()

	testPEM := "-----BEGIN X509 CRL-----\nMIIF...\n-----END X509 CRL-----"

	path, err := SaveCRLToFile(testPEM, tmpDir, "test-ca")
	if err != nil {
		t.Fatalf("SaveCRLToFile failed: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("File not created: %v", err)
	}

	loaded, err := LoadCRLFromFile(path)
	if err != nil {
		t.Fatalf("LoadCRLFromFile failed: %v", err)
	}

	if loaded != testPEM {
		t.Errorf("Loaded PEM = %v, want %v", loaded, testPEM)
	}
}
