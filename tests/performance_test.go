package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// TestPerformance1000Certificates тестирует выпуск 1000 сертификатов
func TestPerformance1000Certificates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Performance Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}

	var rootCert *x509.Certificate
	rootCert, err = x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse root cert: %v", err)
	}
	_ = rootCert

	numCerts := 1000
	startTime := time.Now()

	for i := 0; i < numCerts; i++ {
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate client key %d: %v", i, err)
		}

		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1000)),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("test%d.example.com", i),
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		_, err = x509.CreateCertificate(rand.Reader, clientTemplate, rootTemplate, &clientKey.PublicKey, rootKey)
		if err != nil {
			t.Fatalf("Failed to create client cert %d: %v", i, err)
		}

		if (i+1)%100 == 0 {
			t.Logf("Issued %d/%d certificates", i+1, numCerts)
		}
	}

	duration := time.Since(startTime)
	certsPerSecond := float64(numCerts) / duration.Seconds()

	t.Logf("========================================")
	t.Logf("Performance Test Results:")
	t.Logf("  Certificates issued: %d", numCerts)
	t.Logf("  Total time: %v", duration)
	t.Logf("  Certificates/second: %.2f", certsPerSecond)
	t.Logf("========================================")

	if certsPerSecond < 5 {
		t.Logf("Warning: Performance is %.2f certs/sec (acceptable for development)", certsPerSecond)
	}
}

// TestPerformanceCertificateValidation тестирует проверку 1000 сертификатов
func TestPerformanceCertificateValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Performance Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}

	var rootCert *x509.Certificate
	rootCert, err = x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse root cert: %v", err)
	}

	certs := make([]*x509.Certificate, 1000)
	for i := 0; i < 1000; i++ {
		clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate client key %d: %v", i, err)
		}

		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1000)),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("test%d.example.com", i),
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, rootTemplate, &clientKey.PublicKey, rootKey)
		if err != nil {
			t.Fatalf("Failed to create client cert %d: %v", i, err)
		}

		certs[i], err = x509.ParseCertificate(clientCertBytes)
		if err != nil {
			t.Fatalf("Failed to parse client cert %d: %v", i, err)
		}
	}

	startTime := time.Now()

	for i, cert := range certs {
		err := cert.CheckSignatureFrom(rootCert)
		if err != nil {
			t.Errorf("Certificate %d validation failed: %v", i, err)
		}

		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			t.Errorf("Certificate %d is not valid at current time", i)
		}

		if (i+1)%100 == 0 {
			t.Logf("Validated %d/%d certificates", i+1, len(certs))
		}
	}

	duration := time.Since(startTime)
	validationsPerSecond := float64(len(certs)) / duration.Seconds()

	t.Logf("========================================")
	t.Logf("Validation Performance Test Results:")
	t.Logf("  Certificates validated: %d", len(certs))
	t.Logf("  Total time: %v", duration)
	t.Logf("  Validations/second: %.2f", validationsPerSecond)
	t.Logf("========================================")

	if validationsPerSecond < 100 {
		t.Logf("Warning: Validation performance is %.2f val/sec (expected >= 100)", validationsPerSecond)
	}
}
