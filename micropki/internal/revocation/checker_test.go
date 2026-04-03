package revocation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateTestCertificate создает тестовый сертификат
func generateTestCertificate(t *testing.T, subject string) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

// TestRevocationStatusString тестирует строковое представление статуса
func TestRevocationStatusString(t *testing.T) {
	tests := []struct {
		status   RevocationStatus
		expected string
	}{
		{StatusGood, "good"},
		{StatusRevoked, "revoked"},
		{StatusUnknown, "unknown"},
		{RevocationStatus(99), "unknown"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("Status %d String() = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

// TestNewRevocationChecker тестирует создание проверяльщика
func TestNewRevocationChecker(t *testing.T) {
	config := RevocationCheckerConfig{}
	checker := NewRevocationChecker(config)

	if checker == nil {
		t.Error("NewRevocationChecker returned nil")
	}
	if checker.crlChecker == nil {
		t.Error("crlChecker is nil")
	}
	if checker.ocspChecker == nil {
		t.Error("ocspChecker is nil")
	}
}

// TestCheckRevocation_NoURLs тестирует проверку без URL
func TestCheckRevocation_NoURLs(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test.example.com")
	issuer, _ := generateTestCertificate(t, "Issuer CA")

	config := RevocationCheckerConfig{}
	checker := NewRevocationChecker(config)

	result := checker.CheckRevocation(cert, issuer)

	if result == nil {
		t.Fatal("CheckRevocation returned nil")
	}

	if result.Status != StatusUnknown {
		t.Errorf("Expected StatusUnknown, got %s", result.Status)
	}
}

// TestGetCRLURLs тестирует извлечение URL из сертификата
func TestGetCRLURLs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{
			"http://example.com/crl.pem",
			"http://backup.example.com/crl.pem",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	urls := getCRLURLs(cert)

	if len(urls) != 2 {
		t.Errorf("Expected 2 URLs, got %d", len(urls))
	}
	if urls[0] != "http://example.com/crl.pem" {
		t.Errorf("Expected first URL 'http://example.com/crl.pem', got %s", urls[0])
	}
}
