package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// TestExpiredCertificate проверяет обработку просроченного сертификата
func TestExpiredCertificate(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		t.Logf("✓ Certificate is expired (as expected)")
	} else {
		t.Errorf("Certificate should be expired")
	}
}

// TestWrongKeyUsage проверяет неправильное использование ключа
func TestWrongKeyUsage(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	serverUsage := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverUsage = true
			break
		}
	}

	if !serverUsage {
		t.Logf("✓ Certificate cannot be used for server (as expected)")
	} else {
		t.Errorf("Certificate should not have server usage")
	}
}

// TestMalformedInputs проверяет обработку некорректных входных данных
func TestMalformedInputs(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "malformed-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	malformedPEM := `-----BEGIN CERTIFICATE-----
invalid base64 data that is not valid
-----END CERTIFICATE-----`

	malformedPath := tempDir + "/malformed.pem"
	if err := os.WriteFile(malformedPath, []byte(malformedPEM), 0644); err != nil {
		t.Fatalf("Failed to write malformed PEM: %v", err)
	}

	data, err := os.ReadFile(malformedPath)
	if err != nil {
		t.Fatalf("Failed to read malformed PEM: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Logf("✓ Malformed PEM correctly rejected")
	} else {
		t.Errorf("Malformed PEM should be rejected")
	}

	invalidCSR := []byte("not a valid CSR")
	invalidPath := tempDir + "/invalid.csr"
	if err := os.WriteFile(invalidPath, invalidCSR, 0644); err != nil {
		t.Fatalf("Failed to write invalid CSR: %v", err)
	}

	data, err = os.ReadFile(invalidPath)
	if err != nil {
		t.Fatalf("Failed to read invalid CSR: %v", err)
	}

	_, err = x509.ParseCertificateRequest(data)
	if err != nil {
		t.Logf("✓ Invalid CSR correctly rejected: %v", err)
	} else {
		t.Errorf("Invalid CSR should be rejected")
	}
}
