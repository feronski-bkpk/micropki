package revocation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"micropki/micropki/internal/crl"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseCDP тестирует парсинг CDP расширения
func TestParseCDP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	parser := &CDPParser{}
	urls, err := parser.ParseCDP(cert)
	if err != nil {
		t.Errorf("ParseCDP failed: %v", err)
	}
	t.Logf("CDP URLs: %v", urls)
}

// TestHasCRLDistributionPoint тестирует наличие CDP
func TestHasCRLDistributionPoint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	parser := &CDPParser{}
	has := parser.HasCRLDistributionPoint(cert)
	if !has {
		t.Error("Expected HasCRLDistributionPoint to return true")
	}
}

// createTestCertWithCRL создает тестовый сертификат с CDP
func createTestCertWithCRL(t *testing.T, cdpURL string) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{cdpURL},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

// createTestCAForRevocation создает тестовый CA для тестов отзыва
func createTestCAForRevocation(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		Issuer:                pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

type testLogger struct{}

func (l testLogger) Printf(format string, v ...interface{}) {}

func TestNormalizeCRLURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/crl.pem", "http://example.com/crl.pem"},
		{"https://example.com/crl.pem", "https://example.com/crl.pem"},
		{"file:///path/to/crl.pem", "file:///path/to/crl.pem"},
	}

	for _, tt := range tests {
		result := normalizeCRLURL(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeCRLURL(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// TestGetOCSPURL тестирует получение OCSP URL
func TestGetOCSPURL(t *testing.T) {
	cert, _ := createTestCertWithCRL(t, "http://crl.example.com/crl.pem")
	url := getOCSPURL(cert)
	t.Logf("OCSP URL: %q", url)
}

// TestCRLChecker_CheckWithLocalCRL тестирует проверку CRL с локальным файлом
func TestCRLChecker_CheckWithLocalCRL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crl_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCert, caKey, err := createTestCAForRevocation(t)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	cert, _ := createTestCertWithCRL(t, "http://localhost:8080/crl.pem")

	revokedCerts := []crl.RevokedCertificate{
		{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		},
	}

	crlConfig := &crl.CRLConfig{
		IssuerCert:   caCert,
		IssuerKey:    caKey,
		CRLNumber:    1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(7 * 24 * time.Hour),
		RevokedCerts: revokedCerts,
	}

	generatedCRL, err := crl.GenerateCRL(crlConfig)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, []byte(generatedCRL.PEM), 0644); err != nil {
		t.Fatalf("Failed to write CRL: %v", err)
	}

	config := RevocationCheckerConfig{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		Logger:     testLogger{},
	}
	checker := NewCRLChecker(config)

	result := checker.Check(cert, caCert)
	t.Logf("CRL check result: %v", result)
}

// TestCRLChecker_CheckValid тестирует проверку валидного сертификата
func TestCRLChecker_CheckValid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "crl_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCert, caKey, err := createTestCAForRevocation(t)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	cert, _ := createTestCertWithCRL(t, "http://localhost:8080/crl.pem")

	crlConfig := &crl.CRLConfig{
		IssuerCert:   caCert,
		IssuerKey:    caKey,
		CRLNumber:    1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(7 * 24 * time.Hour),
		RevokedCerts: []crl.RevokedCertificate{},
	}

	generatedCRL, err := crl.GenerateCRL(crlConfig)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, []byte(generatedCRL.PEM), 0644); err != nil {
		t.Fatalf("Failed to write CRL: %v", err)
	}

	config := RevocationCheckerConfig{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		Logger:     testLogger{},
	}
	checker := NewCRLChecker(config)

	result := checker.Check(cert, caCert)
	t.Logf("CRL check for valid cert: %v", result)
}
