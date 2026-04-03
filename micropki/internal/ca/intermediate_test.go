package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/crypto"
)

// createTestRootCA создает тестовый корневой CA для тестов (использует 4096 бит)
func createTestRootCA(t *testing.T, dir string) (string, string, []byte) {
	certsDir := filepath.Join(dir, "certs")
	privateDir := filepath.Join(dir, "private")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		t.Fatalf("Failed to create private dir: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}

	certPath := filepath.Join(certsDir, "ca.cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		t.Fatalf("Failed to save root cert: %v", err)
	}

	keyPath := filepath.Join(privateDir, "ca.key.pem")
	passphrase := []byte("testpass123")
	if err := crypto.SaveEncryptedPrivateKey(key, keyPath, passphrase); err != nil {
		t.Fatalf("Failed to save root key: %v", err)
	}

	return certPath, keyPath, passphrase
}

// TestIssueIntermediate тестирует создание промежуточного CA
func TestIssueIntermediate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ca_intermediate_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsDir := filepath.Join(tmpDir, "certs")
	privateDir := filepath.Join(tmpDir, "private")
	crlDir := filepath.Join(tmpDir, "crl")
	auditDir := filepath.Join(tmpDir, "audit")

	for _, dir := range []string{certsDir, privateDir, crlDir, auditDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", dir, err)
		}
	}

	rootCertPath, rootKeyPath, rootPass := createTestRootCA(t, tmpDir)

	cfg := &CAConfig{
		RootCertPath:   rootCertPath,
		RootKeyPath:    rootKeyPath,
		RootPassphrase: rootPass,
		Subject: &pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("intpass123"),
		OutDir:       tmpDir,
		ValidityDays: 1825,
		PathLen:      0,
	}

	err = IssueIntermediate(cfg)
	if err != nil {
		t.Errorf("IssueIntermediate failed: %v", err)
	}

	certPath := filepath.Join(tmpDir, "certs", "intermediate.cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Intermediate certificate not created at %s", certPath)
	} else {
		t.Logf("Certificate created at %s", certPath)
	}

	keyPath := filepath.Join(tmpDir, "private", "intermediate.key.pem")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Intermediate key not created at %s", keyPath)
	} else {
		t.Logf("Key created at %s", keyPath)
	}
}

// TestIssueIntermediate_InvalidValidity тестирует создание промежуточного CA с недопустимым сроком
func TestIssueIntermediate_InvalidValidity(t *testing.T) {
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
			CommonName: "Test Intermediate CA",
		},
		KeyType:      "rsa",
		KeySize:      4096,
		Passphrase:   []byte("intpass123"),
		OutDir:       tmpDir,
		ValidityDays: 4000,
		PathLen:      0,
	}

	err = IssueIntermediate(cfg)
	if err == nil {
		t.Error("Expected error for invalid validity period, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}

// TestIssueIntermediate_InvalidKeySize тестирует создание с недопустимым размером ключа
func TestIssueIntermediate_InvalidKeySize(t *testing.T) {
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
			CommonName: "Test Intermediate CA",
		},
		KeyType:      "rsa",
		KeySize:      2048,
		Passphrase:   []byte("intpass123"),
		OutDir:       tmpDir,
		ValidityDays: 1825,
		PathLen:      0,
	}

	err = IssueIntermediate(cfg)
	if err == nil {
		t.Error("Expected error for invalid key size, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}
