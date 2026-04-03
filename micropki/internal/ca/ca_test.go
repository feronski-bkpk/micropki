package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/crypto"
	"micropki/micropki/internal/csr"
	"micropki/micropki/internal/database"
	"micropki/micropki/internal/templates"
)

// TestInsertCertificateIntoDB тестирует вставку сертификата в БД
func TestInsertCertificateIntoDB(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	err = InsertCertificateIntoDB(dbPath, cert, certPEM, nil)
	if err != nil {
		t.Errorf("InsertCertificateIntoDB failed: %v", err)
	}

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	serialHex := hex.EncodeToString(cert.SerialNumber.Bytes())
	record, err := db.GetCertificateBySerial(serialHex)
	if err != nil {
		t.Errorf("Failed to get certificate: %v", err)
	}
	if record == nil {
		t.Error("Certificate not found in DB")
	}
}

// TestInsertCertificateIntoDB_Existing тестирует вставку уже существующего сертификата
func TestInsertCertificateIntoDB_Existing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	err = InsertCertificateIntoDB(dbPath, cert, certPEM, nil)
	if err != nil {
		t.Errorf("First insert failed: %v", err)
	}

	err = InsertCertificateIntoDB(dbPath, cert, certPEM, nil)
	if err != nil {
		t.Errorf("Second insert should succeed: %v", err)
	}
}

// TestGenerateCertFilename тестирует генерацию имен файлов
func TestGenerateCertFilename(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		tmplType templates.TemplateType
		expected string
	}{
		{
			name: "server with DNS name",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com"},
			},
			tmplType: templates.Server,
			expected: "example.com",
		},
		{
			name: "client with email (email sanitized)",
			cert: &x509.Certificate{
				EmailAddresses: []string{"user@example.com"},
			},
			tmplType: templates.Client,
			expected: "user_example.com",
		},
		{
			name: "with CommonName",
			cert: &x509.Certificate{
				Subject: pkix.Name{CommonName: "test.local"},
			},
			tmplType: templates.CodeSigning,
			expected: "test.local",
		},
		{
			name: "fallback to serial",
			cert: &x509.Certificate{
				SerialNumber: big.NewInt(12345),
			},
			tmplType: templates.Server,
			expected: "cert-3039",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCertFilename(tt.cert, tt.tmplType)
			if result != tt.expected {
				t.Errorf("generateCertFilename() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestSanitizeFilename тестирует очистку имен файлов
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"test.local", "test.local"},
		{"test@example.com", "test_example.com"},
		{"*.example.com", "_.example.com"},
		{"test/name", "test_name"},
		{"test name", "test_name"},
		{"test-name", "test-name"},
		{"test_name", "test_name"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// createTestCAForTest создает тестовый CA для тестов
func createTestCAForTest(t *testing.T, tmpDir string) (string, string, []byte) {
	certsDir := filepath.Join(tmpDir, "certs")
	privateDir := filepath.Join(tmpDir, "private")
	for _, dir := range []string{certsDir, privateDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		Issuer:                pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}

	rootCertPath := filepath.Join(certsDir, "ca.cert.pem")
	if err := certs.SaveCertificate(rootCertDER, rootCertPath); err != nil {
		t.Fatalf("Failed to save root cert: %v", err)
	}

	rootKeyPath := filepath.Join(privateDir, "ca.key.pem")
	passphrase := []byte("rootpass123")
	if err := crypto.SaveEncryptedPrivateKey(rootKey, rootKeyPath, passphrase); err != nil {
		t.Fatalf("Failed to save root key: %v", err)
	}

	intKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		Issuer:                rootTemplate.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intCertDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootTemplate, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate cert: %v", err)
	}

	intCertPath := filepath.Join(certsDir, "intermediate.cert.pem")
	if err := certs.SaveCertificate(intCertDER, intCertPath); err != nil {
		t.Fatalf("Failed to save intermediate cert: %v", err)
	}

	intKeyPath := filepath.Join(privateDir, "intermediate.key.pem")
	intPassphrase := []byte("intpass123")
	if err := crypto.SaveEncryptedPrivateKey(intKey, intKeyPath, intPassphrase); err != nil {
		t.Fatalf("Failed to save intermediate key: %v", err)
	}

	return intCertPath, intKeyPath, intPassphrase
}

// TestIssueCertificateFromCSR тестирует выпуск сертификата из CSR
func TestIssueCertificateFromCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	csrCfg := &csr.GenerateConfig{
		Subject:    &pkix.Name{CommonName: "test.example.com"},
		KeyType:    "rsa",
		KeySize:    2048,
		SANs:       []templates.SAN{{Type: "dns", Value: "test.example.com"}},
		OutKeyPath: filepath.Join(tmpDir, "test.key.pem"),
		OutCSRPath: filepath.Join(tmpDir, "test.csr.pem"),
	}

	_, err = csr.GenerateKeyAndCSR(csrCfg)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Server,
		CSRPath:      csrCfg.OutCSRPath,
		OutDir:       certsDir,
		ValidityDays: 365,
		DBPath:       "",
	}

	err = IssueCertificate(cfg)
	if err != nil {
		t.Errorf("IssueCertificate failed: %v", err)
	}

	certFiles, err := filepath.Glob(filepath.Join(certsDir, "*.cert.pem"))
	if err != nil {
		t.Fatalf("Failed to list certs: %v", err)
	}
	if len(certFiles) == 0 {
		t.Error("No certificate files created")
	}
}

// TestIssueCertificate_InvalidCSR тестирует выпуск с невалидным CSR
func TestIssueCertificate_InvalidCSR(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	invalidCSRPath := filepath.Join(tmpDir, "invalid.csr.pem")
	if err := os.WriteFile(invalidCSRPath, []byte("invalid csr data"), 0644); err != nil {
		t.Fatalf("Failed to write invalid CSR: %v", err)
	}

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Server,
		CSRPath:      invalidCSRPath,
		OutDir:       certsDir,
		ValidityDays: 365,
	}

	err = IssueCertificate(cfg)
	if err == nil {
		t.Error("Expected error for invalid CSR, got nil")
	}
}

// TestIssueCertificate_WithSubject тестирует выпуск сертификата с указанным субъектом
func TestIssueCertificate_WithSubject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Server,
		Subject:      &pkix.Name{CommonName: "test-subject.local"},
		SANs:         []templates.SAN{{Type: "dns", Value: "test-subject.local"}},
		OutDir:       certsDir,
		ValidityDays: 365,
		KeyType:      "rsa",
		KeySize:      2048,
		DBPath:       "",
	}

	err = IssueCertificate(cfg)
	if err != nil {
		t.Errorf("IssueCertificate with subject failed: %v", err)
	}

	certFiles, err := filepath.Glob(filepath.Join(certsDir, "*.cert.pem"))
	if err != nil {
		t.Fatalf("Failed to list certs: %v", err)
	}
	if len(certFiles) == 0 {
		t.Error("No certificate files created")
	}
}

// TestIssueCertificate_ClientTemplate тестирует выпуск клиентского сертификата
func TestIssueCertificate_ClientTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Client,
		Subject:      &pkix.Name{CommonName: "client.local"},
		SANs:         []templates.SAN{{Type: "email", Value: "client@local.com"}},
		OutDir:       certsDir,
		ValidityDays: 365,
		KeyType:      "rsa",
		KeySize:      2048,
		DBPath:       "",
	}

	err = IssueCertificate(cfg)
	if err != nil {
		t.Errorf("IssueCertificate for client failed: %v", err)
	}

	certFiles, err := filepath.Glob(filepath.Join(certsDir, "*.cert.pem"))
	if err != nil {
		t.Fatalf("Failed to list certs: %v", err)
	}
	if len(certFiles) == 0 {
		t.Error("No certificate files created")
	}
}

// TestIssueCertificate_CodeSigningTemplate тестирует выпуск code signing сертификата
func TestIssueCertificate_CodeSigningTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.CodeSigning,
		Subject:      &pkix.Name{CommonName: "codesign.local"},
		OutDir:       certsDir,
		ValidityDays: 365,
		KeyType:      "rsa",
		KeySize:      2048,
		DBPath:       "",
	}

	err = IssueCertificate(cfg)
	if err != nil {
		t.Errorf("IssueCertificate for code signing failed: %v", err)
	}

	certFiles, err := filepath.Glob(filepath.Join(certsDir, "*.cert.pem"))
	if err != nil {
		t.Fatalf("Failed to list certs: %v", err)
	}
	if len(certFiles) == 0 {
		t.Error("No certificate files created")
	}
}

// TestIssueCertificate_WithDB тестирует выпуск сертификата с сохранением в БД
func TestIssueCertificate_WithDB(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Server,
		Subject:      &pkix.Name{CommonName: "db-test.local"},
		SANs:         []templates.SAN{{Type: "dns", Value: "db-test.local"}},
		OutDir:       certsDir,
		ValidityDays: 365,
		KeyType:      "rsa",
		KeySize:      2048,
		DBPath:       dbPath,
	}

	err = IssueCertificate(cfg)
	if err != nil {
		t.Errorf("IssueCertificate with DB failed: %v", err)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file not created")
	}
}

// TestIssueCertificate_InvalidValidity тестирует выпуск с недопустимым сроком
func TestIssueCertificate_InvalidValidity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}

	caCertPath, caKeyPath, caPass := createTestCAForTest(t, tmpDir)

	cfg := &IssueCertificateConfig{
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		CAPassphrase: caPass,
		Template:     templates.Server,
		Subject:      &pkix.Name{CommonName: "test.local"},
		SANs:         []templates.SAN{{Type: "dns", Value: "test.local"}},
		OutDir:       certsDir,
		ValidityDays: 400,
		KeyType:      "rsa",
		KeySize:      2048,
		DBPath:       "",
	}

	err = IssueCertificate(cfg)
	if err == nil {
		t.Error("Expected error for invalid validity period")
	}
}

// TestIssueIntermediate_WithSAN тестирует создание промежуточного CA с SAN
func TestIssueIntermediate_WithSAN(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_intermediate_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, dir := range []string{"certs", "private", "crl", "audit"} {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
			t.Fatalf("Failed to create dir: %v", err)
		}
	}

	rootCertPath, rootKeyPath, rootPass := createTestRootCA(t, tmpDir)

	cfg := &CAConfig{
		RootCertPath:   rootCertPath,
		RootKeyPath:    rootKeyPath,
		RootPassphrase: rootPass,
		Subject: &pkix.Name{
			CommonName: "Test Intermediate CA with SAN",
		},
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("intpass123"),
		OutDir:       tmpDir,
		ValidityDays: 1825,
		PathLen:      0,
		SANs:         []templates.SAN{{Type: "dns", Value: "intermediate.local"}},
	}

	err = IssueIntermediate(cfg)
	if err != nil {
		t.Errorf("IssueIntermediate with SAN failed: %v", err)
	}

	certPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Intermediate certificate not created")
	}
}
