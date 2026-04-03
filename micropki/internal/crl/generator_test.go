package crl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// createTestCAForCRL создает тестовый CA для тестов CRL
func createTestCAForCRL(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
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
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	return cert, key
}

// TestGenerateCRL_Valid тестирует генерацию корректного CRL
func TestGenerateCRL_Valid(t *testing.T) {
	caCert, caKey := createTestCAForCRL(t)

	cfg := &CRLConfig{
		IssuerCert:              caCert,
		IssuerKey:               caKey,
		ThisUpdate:              time.Now(),
		NextUpdate:              time.Now().Add(8 * 24 * time.Hour),
		CRLNumber:               1,
		RevokedCerts:            []RevokedCertificate{},
		IncludeReasonExtensions: false,
	}

	crl, err := GenerateCRL(cfg)
	if err != nil {
		t.Errorf("GenerateCRL failed: %v", err)
	}
	if crl == nil {
		t.Error("Generated CRL is nil")
	}
}

// TestGenerateCRL_WithRevokedCerts тестирует генерацию CRL с отозванными сертификатами
func TestGenerateCRL_WithRevokedCerts(t *testing.T) {
	caCert, caKey := createTestCAForCRL(t)

	revokedCerts := []RevokedCertificate{
		{
			SerialNumber:   big.NewInt(12345),
			RevocationTime: time.Now(),
		},
		{
			SerialNumber:   big.NewInt(67890),
			RevocationTime: time.Now(),
		},
	}

	cfg := &CRLConfig{
		IssuerCert:              caCert,
		IssuerKey:               caKey,
		ThisUpdate:              time.Now(),
		NextUpdate:              time.Now().Add(8 * 24 * time.Hour),
		CRLNumber:               1,
		RevokedCerts:            revokedCerts,
		IncludeReasonExtensions: false,
	}

	crl, err := GenerateCRL(cfg)
	if err != nil {
		t.Errorf("GenerateCRL with revoked certs failed: %v", err)
	}
	if crl == nil {
		t.Error("Generated CRL is nil")
	}
}

// TestGenerateCRL_MissingNextUpdate тестирует генерацию без NextUpdate
func TestGenerateCRL_MissingNextUpdate(t *testing.T) {
	caCert, caKey := createTestCAForCRL(t)

	cfg := &CRLConfig{
		IssuerCert:              caCert,
		IssuerKey:               caKey,
		ThisUpdate:              time.Now(),
		NextUpdate:              time.Time{},
		CRLNumber:               1,
		RevokedCerts:            []RevokedCertificate{},
		IncludeReasonExtensions: false,
	}

	_, err := GenerateCRL(cfg)
	if err == nil {
		t.Error("Expected error for missing NextUpdate")
	}
}

// TestVerifyCRL_Valid тестирует проверку валидного CRL
func TestVerifyCRL_Valid(t *testing.T) {
	caCert, caKey := createTestCAForCRL(t)

	cfg := &CRLConfig{
		IssuerCert:              caCert,
		IssuerKey:               caKey,
		ThisUpdate:              time.Now(),
		NextUpdate:              time.Now().Add(8 * 24 * time.Hour),
		CRLNumber:               1,
		RevokedCerts:            []RevokedCertificate{},
		IncludeReasonExtensions: false,
	}

	crl, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	err = VerifyCRL([]byte(crl.PEM), caCert)
	if err != nil {
		t.Errorf("VerifyCRL failed: %v", err)
	}
}

// TestVerifyCRL_Invalid тестирует проверку невалидного CRL
func TestVerifyCRL_Invalid(t *testing.T) {
	caCert, _ := createTestCAForCRL(t)

	invalidCRL := []byte("invalid crl data")
	err := VerifyCRL(invalidCRL, caCert)
	if err == nil {
		t.Error("Expected error for invalid CRL")
	}
}

// TestVerifyCRL_WrongIssuer тестирует проверку CRL с неверным издателем
func TestVerifyCRL_WrongIssuer(t *testing.T) {
	caCert1, caKey1 := createTestCAForCRL(t)
	caCert2, _ := createTestCAForCRL(t)

	cfg := &CRLConfig{
		IssuerCert:              caCert1,
		IssuerKey:               caKey1,
		ThisUpdate:              time.Now(),
		NextUpdate:              time.Now().Add(8 * 24 * time.Hour),
		CRLNumber:               1,
		RevokedCerts:            []RevokedCertificate{},
		IncludeReasonExtensions: false,
	}

	crl, err := GenerateCRL(cfg)
	if err != nil {
		t.Fatalf("Failed to generate CRL: %v", err)
	}

	err = VerifyCRL([]byte(crl.PEM), caCert2)
	if err == nil {
		t.Error("Expected error for wrong issuer")
	}
}
