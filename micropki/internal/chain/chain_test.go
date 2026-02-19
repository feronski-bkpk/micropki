// Package chain tests
package chain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(isCA bool, commonName string, signingKey *rsa.PrivateKey, signingCert *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create template
	serialNumber := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	var issuerCert *x509.Certificate
	var issuerKey *rsa.PrivateKey

	if signingCert != nil {
		issuerCert = signingCert
		issuerKey = signingKey
	} else {
		// Self-signed
		issuerCert = template
		issuerKey = key
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	return cert, key, err
}

func TestChainVerification(t *testing.T) {
	// Generate Root CA
	rootCert, rootKey, err := generateTestCert(true, "Test Root CA", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Generate Intermediate CA signed by Root
	intermediateCert, intermediateKey, err := generateTestCert(true, "Test Intermediate CA", rootKey, rootCert)
	if err != nil {
		t.Fatalf("Failed to generate intermediate CA: %v", err)
	}

	// Generate Leaf certificate signed by Intermediate
	leafCert, _, err := generateTestCert(false, "test.example.com", intermediateKey, intermediateCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	// Create chain
	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: intermediateCert,
		Root:         rootCert,
	}

	// Verify chain
	if err := chain.Verify(); err != nil {
		t.Errorf("Chain verification failed: %v", err)
	}
}

func TestInvalidChain(t *testing.T) {
	// Generate two independent CAs
	root1Cert, _, err := generateTestCert(true, "Test Root CA 1", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate root CA 1: %v", err)
	}

	root2Cert, root2Key, err := generateTestCert(true, "Test Root CA 2", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate root CA 2: %v", err)
	}

	// Generate leaf signed by root2
	leafCert, _, err := generateTestCert(false, "test.example.com", root2Key, root2Cert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	// Create mismatched chain (leaf signed by root2, but root1 as root)
	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: root2Cert, // Using root2 as intermediate
		Root:         root1Cert,
	}

	// Verification should fail
	if err := chain.Verify(); err == nil {
		t.Error("Expected chain verification to fail, but it succeeded")
	}
}
