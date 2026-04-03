package revocation

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
)

// TestNewCRLChecker тестирует создание CRL проверяльщика
func TestNewCRLChecker(t *testing.T) {
	config := RevocationCheckerConfig{}
	checker := NewCRLChecker(config)

	if checker == nil {
		t.Error("NewCRLChecker returned nil")
	}
	if checker.client == nil {
		t.Error("HTTP client is nil")
	}
}

// TestParseCRL тестирует парсинг CRL
func TestParseCRL(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	revokedCerts := []pkix.RevokedCertificate{}
	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(7 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "crl_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("Failed to write CRL: %v", err)
	}

	data, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("Failed to read CRL: %v", err)
	}

	crl, err := parseCRL(data)
	if err != nil {
		t.Errorf("parseCRL failed: %v", err)
	}

	if crl == nil {
		t.Error("parseCRL returned nil")
	}
}

// TestGetCRLURLs_Empty тестирует пустые URL
func TestGetCRLURLs_Empty(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test.example.com")
	urls := getCRLURLs(cert)

	if len(urls) != 0 {
		t.Errorf("Expected 0 URLs, got %d", len(urls))
	}
}
