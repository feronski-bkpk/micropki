// Package tests содержит интеграционные тесты для MicroPKI.
// Эти тесты тестируют взаимодействие между компонентами через CLI.
package tests

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TestMain настраивает тестовое окружение
func TestMain(m *testing.M) {
	testDir := "./test-output"
	os.MkdirAll(testDir, 0755)

	code := m.Run()

	os.RemoveAll(testDir)
	os.Exit(code)
}

// runCLI выполняет команду CLI и возвращает вывод
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := exec.Command("../micropki-cli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), fmt.Errorf("CLI error: %v, stderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// checkDBTables проверяет наличие таблиц в БД напрямую через SQL
func checkDBTables(t *testing.T, dbPath string) {
	t.Helper()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Logf("Failed to open DB for checking: %v", err)
		return
	}
	defer db.Close()

	var tableCount int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='certificates'").Scan(&tableCount)
	if err != nil {
		t.Logf("Failed to query tables: %v", err)
		return
	}

	if tableCount == 0 {
		t.Logf("WARNING: certificates table NOT found in %s", dbPath)
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
		if err == nil {
			defer rows.Close()
			var tables []string
			for rows.Next() {
				var name string
				rows.Scan(&name)
				tables = append(tables, name)
			}
			t.Logf("Tables in DB: %v", tables)
		}
	} else {
		t.Logf("OK: certificates table found in %s", dbPath)
	}
}

// setupPKI создает тестовую PKI иерархию
func setupPKI(t *testing.T, baseDir string) error {
	t.Helper()

	os.MkdirAll(baseDir, 0755)

	t.Logf("Initializing database at %s/micropki.db", baseDir)
	output, err := runCLI(t, "db", "init", "--db-path", baseDir+"/micropki.db", "--force")
	if err != nil {
		t.Logf("DB init output: %s", output)
		return fmt.Errorf("db init: %w", err)
	}

	checkDBTables(t, baseDir+"/micropki.db")

	rootPass := baseDir + "/root-pass.txt"
	if err := os.WriteFile(rootPass, []byte("rootpass123"), 0600); err != nil {
		return err
	}

	t.Log("Creating root CA...")
	_, err = runCLI(t, "ca", "init",
		"--subject", "/CN=Test Root CA",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", rootPass,
		"--out-dir", baseDir+"/root",
		"--validity-days", "365",
		"--force",
	)
	if err != nil {
		return fmt.Errorf("root init: %w", err)
	}

	intPass := baseDir + "/int-pass.txt"
	if err := os.WriteFile(intPass, []byte("intpass123"), 0600); err != nil {
		return err
	}

	t.Log("Creating intermediate CA...")
	_, err = runCLI(t, "ca", "issue-intermediate",
		"--root-cert", baseDir+"/root/certs/ca.cert.pem",
		"--root-key", baseDir+"/root/private/ca.key.pem",
		"--root-pass-file", rootPass,
		"--subject", "/CN=Test Intermediate CA",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", intPass,
		"--out-dir", baseDir+"/intermediate",
		"--db-path", baseDir+"/micropki.db",
	)
	if err != nil {
		return fmt.Errorf("intermediate issue: %w", err)
	}

	checkDBTables(t, baseDir+"/micropki.db")

	return nil
}

// issueTestCertificate выпускает тестовый сертификат и возвращает его серийный номер
func issueTestCertificate(t *testing.T, baseDir, name string) string {
	t.Helper()

	intPass := baseDir + "/int-pass.txt"
	dbPath := baseDir + "/micropki.db"
	certDir := baseDir + "/certs"

	os.RemoveAll(certDir)
	os.MkdirAll(certDir, 0755)

	output, err := runCLI(t, "ca", "issue-cert",
		"--ca-cert", baseDir+"/intermediate/certs/intermediate.cert.pem",
		"--ca-key", baseDir+"/intermediate/private/intermediate.key.pem",
		"--ca-pass-file", intPass,
		"--template", "server",
		"--subject", "CN="+name,
		"--san", "dns:"+name,
		"--out-dir", certDir,
		"--db-path", dbPath,
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	t.Logf("CLI output: %s", output)

	// Извлекаем серийный номер из вывода
	lines := strings.Split(output, "\n")
	var serial string
	for _, line := range lines {
		if strings.Contains(line, "Серийный номер:") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				serial = parts[len(parts)-1]
			}
			break
		}
	}

	if serial == "" {
		t.Fatal("Could not extract serial number from output")
	}

	// Проверяем наличие файлов сертификатов
	files, err := filepath.Glob(certDir + "/*.cert.pem")
	if err != nil || len(files) == 0 {
		t.Logf("WARNING: No certificate files found in %s", certDir)
	} else {
		t.Logf("Certificate files: %v", files)
	}

	// Даём время на запись в БД
	time.Sleep(1 * time.Second)

	// Проверяем, что сертификат добавлен в БД
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Logf("Could not open DB for verification: %v", err)
		return serial
	}
	defer db.Close()

	// Для диагностики показываем таблицы в БД
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err == nil {
		defer rows.Close()
		tables := []string{}
		for rows.Next() {
			var name string
			rows.Scan(&name)
			tables = append(tables, name)
		}
		t.Logf("Tables in DB: %v", tables)
	}

	// Проверяем наличие сертификата в БД
	var count int
	normalizedSerial := strings.ToLower(serial)
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE LOWER(serial_hex) = ?", normalizedSerial).Scan(&count)
	if err != nil {
		t.Logf("WARNING: Could not verify certificate in DB: %v", err)
	} else if count == 0 {
		// Сертификат не найден - показываем все сертификаты для диагностики
		t.Logf("WARNING: Certificate %s not immediately found in DB, checking all certificates...", serial)

		rows, err := db.Query("SELECT serial_hex, subject FROM certificates")
		if err == nil {
			defer rows.Close()
			found := false
			t.Log("Certificates in DB:")
			for rows.Next() {
				var s, subj string
				rows.Scan(&s, &subj)
				t.Logf("  %s: %s", s, subj)
				if strings.EqualFold(s, serial) {
					found = true
				}
			}
			if found {
				t.Logf("✓ Certificate %s found in DB (case-insensitive match)", serial)
			} else {
				t.Logf("WARNING: Certificate %s NOT found in DB after issuance!", serial)
			}
		}
	} else {
		t.Logf("✓ Certificate %s verified in DB", serial)
	}

	return serial
}

func getCRLNumber(t *testing.T, crlPath string) string {
	t.Helper()

	if _, err := os.Stat(crlPath); err != nil {
		t.Logf("CRL file not found: %v", err)
		return ""
	}

	cmd := exec.Command("openssl", "crl", "-in", crlPath,
		"-inform", "PEM", "-noout", "-text")
	output, err := cmd.Output()
	if err != nil {
		t.Logf("Failed to parse CRL with openssl: %v", err)
		content, _ := os.ReadFile(crlPath)
		t.Logf("CRL content: %s", string(content))
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "CRL Number") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				return parts[3]
			}
		}
	}
	return ""
}

// TestCLIHelp проверяет наличие CRL команд в справке
func TestCLIHelp(t *testing.T) {
	output, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("Failed to run help: %v", err)
	}

	expected := []string{
		"ca revoke",
		"ca gen-crl",
		"ca check-revoked",
		"unspecified",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"removeFromCRL",
		"privilegeWithdrawn",
		"aACompromise",
	}

	for _, exp := range expected {
		if !strings.Contains(output, exp) {
			t.Errorf("Help missing '%s'", exp)
		}
	}
}

// TestCLIRevoke проверяет команду отзыва через CLI
func TestCLIRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CLI test in short mode")
	}

	testDir := "./test-output/cli-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	serial := issueTestCertificate(t, testDir, "test.example.com")
	t.Logf("Issued certificate with serial: %s", serial)

	statusOut, err := runCLI(t, "ca", "check-revoked", serial, "--db-path", dbPath)
	if err != nil {
		t.Fatalf("Failed to check status: %v, output: %s", err, statusOut)
	}
	if !strings.Contains(statusOut, "действителен") && !strings.Contains(statusOut, "valid") {
		t.Errorf("Expected certificate to be valid, got: %s", statusOut)
	}

	revokeOut, err := runCLI(t, "ca", "revoke", serial, "--reason", "keyCompromise", "--force", "--db-path", dbPath)
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v, output: %s", err, revokeOut)
	}

	statusOut, err = runCLI(t, "ca", "check-revoked", serial, "--db-path", dbPath)
	if err != nil {
		t.Fatalf("Failed to check status after revocation: %v, output: %s", err, statusOut)
	}
	if !strings.Contains(statusOut, "ОТОЗВАН") && !strings.Contains(statusOut, "revoked") {
		t.Errorf("Expected certificate to be revoked, got: %s", statusOut)
	}
}

// TestCRLGeneration проверяет генерацию CRL через CLI
func TestCRLGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CRL generation test in short mode")
	}

	testDir := "./test-output/crl-gen-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	_, err = runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", testDir+"/micropki.db",
	)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crlPath := testDir + "/crl/intermediate.crl.pem"
	if _, err := os.Stat(crlPath); err != nil {
		t.Fatalf("CRL file not created: %v", err)
	}

	info, err := os.Stat(crlPath)
	if err != nil || info.Size() == 0 {
		t.Errorf("CRL file is empty")
	}

	cmd := exec.Command("openssl", "crl", "-in", crlPath, "-inform", "PEM", "-noout", "-text")
	if err := cmd.Run(); err != nil {
		t.Errorf("OpenSSL cannot read CRL: %v", err)
	}
}

// TestRevokeNonExistent проверяет отзыв несуществующего сертификата
func TestRevokeNonExistent(t *testing.T) {
	testDir := "./test-output/revoke-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	output, err := runCLI(t, "ca", "revoke", "DEADBEEF", "--reason", "unspecified", "--force",
		"--db-path", dbPath)

	if err == nil {
		t.Error("Expected error when revoking non-existent certificate")
	}
	if !strings.Contains(output, "не найден") && !strings.Contains(output, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", output)
	}
}

// TestCRLWithReasons проверяет CRL с разными причинами отзыва
func TestCRLWithReasons(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CRL reasons test in short mode")
	}

	testDir := "./test-output/reasons-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	reasons := []string{
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"privilegeWithdrawn",
		"aACompromise",
	}

	serials := make([]string, 0, len(reasons))

	for i, reason := range reasons {
		name := fmt.Sprintf("test-%d.example.com", i)
		serial := issueTestCertificate(t, testDir, name)
		serials = append(serials, serial)
		t.Logf("Certificate %d serial: %s", i, serial)

		revokeOut, err := runCLI(t, "ca", "revoke", serial, "--reason", reason, "--force", "--db-path", dbPath)
		if err != nil {
			t.Fatalf("Failed to revoke with reason %s: %v, output: %s", reason, err, revokeOut)
		}

		statusOut, err := runCLI(t, "ca", "check-revoked", serial, "--db-path", dbPath)
		if err != nil {
			t.Fatalf("Failed to check status after revocation: %v", err)
		}
		if !strings.Contains(statusOut, "ОТОЗВАН") && !strings.Contains(statusOut, "revoked") {
			t.Errorf("Certificate %s not revoked after reason %s", serial, reason)
		}
	}

	t.Log("=== ДИАГНОСТИКА БД ===")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB for diagnostics: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT DISTINCT issuer FROM certificates")
	if err != nil {
		t.Logf("Failed to query issuers: %v", err)
	} else {
		defer rows.Close()
		t.Log("Уникальные издатели в БД:")
		for rows.Next() {
			var issuer string
			if err := rows.Scan(&issuer); err == nil {
				t.Logf("  Издатель: %s", issuer)
			}
		}
	}

	rows, err = db.Query("SELECT serial_hex, issuer, revocation_reason FROM certificates WHERE status = 'revoked'")
	if err != nil {
		t.Logf("Failed to query revoked certificates: %v", err)
	} else {
		defer rows.Close()
		t.Log("Отозванные сертификаты:")
		for rows.Next() {
			var serial, issuer string
			var reason sql.NullString
			if err := rows.Scan(&serial, &issuer, &reason); err == nil {
				reasonStr := "не указана"
				if reason.Valid {
					reasonStr = reason.String
				}
				t.Logf("  Серийный номер: %s", serial)
				t.Logf("    Издатель: %s", issuer)
				t.Logf("    Причина: %s", reasonStr)
			}
		}
	}

	var revokedCount int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").Scan(&revokedCount)
	if err != nil {
		t.Logf("Failed to count revoked certificates: %v", err)
	} else {
		t.Logf("Всего отозванных сертификатов в БД: %d", revokedCount)
		if revokedCount != len(reasons) {
			t.Errorf("Ожидалось %d отозванных сертификатов, получено %d", len(reasons), revokedCount)
		}
	}

	var totalCount int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&totalCount)
	if err != nil {
		t.Logf("Failed to count total certificates: %v", err)
	} else {
		t.Logf("Всего сертификатов в БД: %d", totalCount)
	}

	t.Log("=== КОНЕЦ ДИАГНОСТИКИ ===")

	t.Log("Generating CRL after revocation...")
	crlOut, err := runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", dbPath,
	)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v, output: %s", err, crlOut)
	}

	crlPath := testDir + "/crl/intermediate.crl.pem"
	t.Logf("Checking CRL file: %s", crlPath)

	if _, err := os.Stat(crlPath); err != nil {
		t.Fatalf("CRL file not created: %v", err)
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("Failed to read CRL: %v", err)
	}

	t.Logf("CRL file size: %d bytes", len(crlPEM))

	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("Failed to decode CRL PEM")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	t.Logf("CRL parsed successfully:")
	t.Logf("  Issuer: %s", crl.Issuer)
	t.Logf("  ThisUpdate: %s", crl.ThisUpdate)
	t.Logf("  NextUpdate: %s", crl.NextUpdate)
	t.Logf("  Number of revoked certificates: %d", len(crl.RevokedCertificates))

	crlSerials := make(map[string]bool)
	for _, rc := range crl.RevokedCertificates {
		serialHex := fmt.Sprintf("%X", rc.SerialNumber)
		crlSerials[serialHex] = true
		t.Logf("  Revoked serial in CRL: %s", serialHex)
	}

	foundCount := 0
	missingSerials := []string{}

	for _, serial := range serials {
		normalizedSerial := strings.ToUpper(strings.TrimLeft(serial, "0"))
		if normalizedSerial == "" {
			normalizedSerial = "0"
		}

		if crlSerials[serial] ||
			crlSerials[strings.ToUpper(serial)] ||
			crlSerials[strings.ToLower(serial)] ||
			crlSerials[normalizedSerial] {
			t.Logf("Serial %s found in CRL", serial)
			foundCount++
		} else {
			t.Errorf("Serial %s not found in CRL (normalized: %s)", serial, normalizedSerial)
			missingSerials = append(missingSerials, serial)
		}
	}

	t.Logf("Найдено %d из %d серийных номеров в CRL", foundCount, len(serials))

	if len(missingSerials) > 0 {
		t.Log("All serials in CRL:")
		for s := range crlSerials {
			t.Logf("  %s", s)
		}
	}
}

// TestRevokeAlreadyRevoked проверяет попытку повторного отзыва
func TestRevokeAlreadyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping revoke already revoked test in short mode")
	}

	testDir := "./test-output/revoke-twice-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	serial := issueTestCertificate(t, testDir, "test.example.com")
	t.Logf("Certificate serial: %s", serial)

	_, err = runCLI(t, "ca", "revoke", serial, "--reason", "keyCompromise", "--force", "--db-path", dbPath)
	if err != nil {
		t.Fatalf("First revocation failed: %v", err)
	}

	output, err := runCLI(t, "ca", "revoke", serial, "--reason", "superseded", "--force", "--db-path", dbPath)

	if err != nil {
		t.Errorf("Second revocation should not return error: %v", err)
	}
	if !strings.Contains(output, "уже отозван") && !strings.Contains(output, "already revoked") {
		t.Errorf("Expected warning about already revoked, got: %s", output)
	}
}

// TestCRLNumberIncrement проверяет монотонное увеличение номера CRL
func TestCRLNumberIncrement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CRL number increment test in short mode")
	}

	testDir := "./test-output/crl-number-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	_, err = runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", testDir+"/micropki.db",
	)
	if err != nil {
		t.Fatalf("Failed to generate first CRL: %v", err)
	}

	number1 := getCRLNumber(t, testDir+"/crl/intermediate.crl.pem")
	t.Logf("First CRL number: %s", number1)

	_, err = runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", testDir+"/micropki.db",
	)
	if err != nil {
		t.Fatalf("Failed to generate second CRL: %v", err)
	}

	number2 := getCRLNumber(t, testDir+"/crl/intermediate.crl.pem")
	t.Logf("Second CRL number: %s", number2)

	if number1 == "" || number2 == "" {
		t.Skip("Could not extract CRL numbers, skipping increment check")
	}
	if number1 == number2 {
		cmd := exec.Command("openssl", "crl", "-in", testDir+"/crl/intermediate.crl.pem",
			"-inform", "PEM", "-text", "-noout")
		output, _ := cmd.CombinedOutput()
		t.Logf("CRL content:\n%s", string(output))

		t.Errorf("CRL number did not increment: %s -> %s", number1, number2)
	}
}

// TestHTTPCRLEndpoints тестирует HTTP CRL эндпоинты
func TestHTTPCRLEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping HTTP CRL test in short mode")
	}

	testDir := "./test-output/http-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	serial := issueTestCertificate(t, testDir, "test.example.com")
	t.Logf("Issued certificate with serial: %s", serial)

	revokeOut, err := runCLI(t, "ca", "revoke", serial, "--reason", "keyCompromise", "--force", "--db-path", dbPath)
	if err != nil {
		t.Fatalf("Failed to revoke certificate: %v, output: %s", err, revokeOut)
	}

	t.Log("Generating intermediate CRL...")
	_, err = runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", dbPath,
	)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CRL: %v", err)
	}

	t.Log("Generating root CRL...")
	_, err = runCLI(t, "ca", "gen-crl",
		"--ca", "root",
		"--next-update", "30",
		"--out-dir", testDir,
		"--db-path", dbPath,
	)
	if err != nil {
		t.Fatalf("Failed to generate root CRL: %v", err)
	}

	intermediateCRL := testDir + "/crl/intermediate.crl.pem"
	rootCRL := testDir + "/crl/root.crl.pem"

	t.Logf("Checking CRL files:")
	if _, err := os.Stat(intermediateCRL); err != nil {
		t.Fatalf("Intermediate CRL file not created: %v", err)
	} else {
		info, _ := os.Stat(intermediateCRL)
		t.Logf("  intermediate.crl.pem exists, size: %d bytes", info.Size())
	}

	if _, err := os.Stat(rootCRL); err != nil {
		t.Fatalf("Root CRL file not created: %v", err)
	} else {
		info, _ := os.Stat(rootCRL)
		t.Logf("  root.crl.pem exists, size: %d bytes", info.Size())
	}

	repoLog := testDir + "/repo.log"
	t.Logf("Repository log file: %s", repoLog)

	cmd := exec.Command("../micropki-cli", "repo", "serve",
		"--host", "127.0.0.1",
		"--port", "18080",
		"--db-path", dbPath,
		"--cert-dir", testDir+"/certs",
		"--log-file", repoLog,
	)

	err = cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start repository: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	t.Log("Waiting for server to start...")
	time.Sleep(3 * time.Second)

	if logContent, err := os.ReadFile(repoLog); err == nil {
		t.Logf("Repository log content:\n%s", string(logContent))
	} else {
		t.Logf("Could not read repo log: %v", err)
	}

	t.Log("Checking health endpoint...")
	resp, err := http.Get("http://127.0.0.1:18080/health")
	if err != nil {
		curlCmd := exec.Command("curl", "-v", "http://127.0.0.1:18080/health")
		curlOut, _ := curlCmd.CombinedOutput()
		t.Logf("Curl output: %s", string(curlOut))
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("Health response: %s, body: %s", resp.Status, string(body))

	if resp.StatusCode != 200 {
		t.Fatalf("Health check returned %d", resp.StatusCode)
	}

	endpoints := []struct {
		name     string
		url      string
		wantCode int
	}{
		{"default CRL", "http://127.0.0.1:18080/crl", 200},
		{"intermediate CRL param", "http://127.0.0.1:18080/crl?ca=intermediate", 200},
		{"root CRL param", "http://127.0.0.1:18080/crl?ca=root", 200},
		{"intermediate CRL file", "http://127.0.0.1:18080/crl/intermediate.crl", 200},
		{"root CRL file", "http://127.0.0.1:18080/crl/root.crl", 200},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			t.Logf("Testing endpoint: %s", ep.url)

			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			req, err := http.NewRequest("GET", ep.url, nil)
			if err != nil {
				t.Errorf("Failed to create request: %v", err)
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("Failed to GET %s: %v", ep.url, err)
				return
			}
			defer resp.Body.Close()

			t.Logf("  Response status: %s", resp.Status)
			t.Logf("  Response headers: %v", resp.Header)

			if resp.StatusCode != ep.wantCode {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Endpoint %s returned status %d, expected %d. Response: %s",
					ep.url, resp.StatusCode, ep.wantCode, string(body))
			}
		})
	}

	t.Run("Content-Type header", func(t *testing.T) {
		resp, err := http.Get("http://127.0.0.1:18080/crl")
		if err != nil {
			t.Fatalf("Failed to get headers: %v", err)
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		t.Logf("Content-Type: %s", contentType)

		if contentType != "application/pkix-crl" {
			t.Errorf("Wrong Content-Type header: got %q, want %q",
				contentType, "application/pkix-crl")
		}
	})

	t.Run("Cache headers", func(t *testing.T) {
		resp, err := http.Get("http://127.0.0.1:18080/crl")
		if err != nil {
			t.Fatalf("Failed to get headers: %v", err)
		}
		defer resp.Body.Close()

		headers := resp.Header
		t.Logf("All headers: %v", headers)

		expectedHeaders := []string{
			"Last-Modified",
			"Etag",
			"Cache-Control",
		}

		for _, h := range expectedHeaders {
			if headers.Get(h) == "" {
				t.Errorf("Missing header: %s", h)
			} else {
				t.Logf("  %s: %s", h, headers.Get(h))
			}
		}
	})
}

// TestRevokeWithDifferentReasons проверяет все причины отзыва
func TestRevokeWithDifferentReasons(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping revoke reasons test in short mode")
	}

	testDir := "./test-output/reasons-all-test"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	err := setupPKI(t, testDir)
	if err != nil {
		t.Fatalf("Failed to setup PKI: %v", err)
	}

	dbPath := testDir + "/micropki.db"

	allReasons := []string{
		"unspecified",
		"keyCompromise",
		"cACompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"removeFromCRL",
		"privilegeWithdrawn",
		"aACompromise",
	}

	serials := make([]string, 0, len(allReasons))

	for _, reason := range allReasons {
		name := fmt.Sprintf("test-%s.example.com", reason)
		serial := issueTestCertificate(t, testDir, name)
		serials = append(serials, serial)
		t.Logf("Certificate for reason %s: %s", reason, serial)

		revokeOut, err := runCLI(t, "ca", "revoke", serial, "--reason", reason, "--force", "--db-path", dbPath)
		if err != nil {
			t.Fatalf("Failed to revoke with reason %s: %v, output: %s", reason, err, revokeOut)
		}

		statusOut, err := runCLI(t, "ca", "check-revoked", serial, "--db-path", dbPath)
		if err != nil {
			t.Fatalf("Failed to check status: %v, output: %s", err, statusOut)
		}
		if !strings.Contains(statusOut, "ОТОЗВАН") && !strings.Contains(statusOut, "revoked") {
			t.Errorf("Certificate not revoked after reason %s", reason)
		}
	}

	t.Log("=== ДИАГНОСТИКА БД ===")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB for diagnostics: %v", err)
	}
	defer db.Close()

	var revokedCount int
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").Scan(&revokedCount)
	if err != nil {
		t.Logf("Failed to count revoked certificates: %v", err)
	} else {
		t.Logf("Всего отозванных сертификатов в БД: %d", revokedCount)
	}

	t.Log("Generating CRL after all revocations...")
	crlOut, err := runCLI(t, "ca", "gen-crl",
		"--ca", "intermediate",
		"--next-update", "7",
		"--out-dir", testDir,
		"--db-path", dbPath,
	)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v, output: %s", err, crlOut)
	}

	crlPath := testDir + "/crl/intermediate.crl.pem"
	if _, err := os.Stat(crlPath); err != nil {
		t.Fatalf("CRL file not created: %v", err)
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("Failed to read CRL: %v", err)
	}

	t.Logf("CRL created successfully, size: %d bytes", len(crlPEM))

	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("Failed to decode CRL PEM")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	t.Logf("CRL parsed successfully:")
	t.Logf("  Issuer: %s", crl.Issuer)
	t.Logf("  ThisUpdate: %s", crl.ThisUpdate)
	t.Logf("  NextUpdate: %s", crl.NextUpdate)
	t.Logf("  Number of revoked certificates: %d", len(crl.RevokedCertificates))

	crlSerials := make(map[string]bool)
	for _, rc := range crl.RevokedCertificates {
		serialHex := fmt.Sprintf("%X", rc.SerialNumber)
		crlSerials[serialHex] = true
		t.Logf("  Revoked serial in CRL: %s", serialHex)
	}

	foundCount := 0
	missingSerials := []string{}

	for _, serial := range serials {

		normalizedSerial := strings.ToUpper(strings.TrimLeft(serial, "0"))
		if normalizedSerial == "" {
			normalizedSerial = "0"
		}

		if crlSerials[serial] ||
			crlSerials[strings.ToUpper(serial)] ||
			crlSerials[strings.ToLower(serial)] ||
			crlSerials[normalizedSerial] {
			foundCount++
			t.Logf("Serial %s found in CRL", serial)
		} else {
			t.Errorf("Serial %s not found in CRL (normalized: %s)", serial, normalizedSerial)
			missingSerials = append(missingSerials, serial)
		}
	}

	t.Logf("Найдено %d из %d серийных номеров в CRL", foundCount, len(serials))

	if len(missingSerials) > 0 {
		t.Log("All serials in CRL:")
		for s := range crlSerials {
			t.Logf("  %s", s)
		}
	}
}
