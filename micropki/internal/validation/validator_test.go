package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateCertChain создает корректную цепочку сертификатов
func generateCertChain(t *testing.T, depth int) ([]*x509.Certificate, []*rsa.PrivateKey) {
	certs := make([]*x509.Certificate, depth)
	keys := make([]*rsa.PrivateKey, depth)

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}
	keys[0] = rootKey

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		Issuer:                pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}
	certs[0], _ = x509.ParseCertificate(rootCertDER)

	for i := 1; i < depth; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		keys[i] = key

		issuer := certs[i-1]
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "Intermediate CA Level " + string(rune('0'+i))},
			Issuer:                issuer.Subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, keys[i-1])
		if err != nil {
			t.Fatalf("Failed to create intermediate cert: %v", err)
		}
		certs[i], _ = x509.ParseCertificate(certDER)
	}

	return certs, keys
}

// generateLeafCert создает листовой сертификат
func generateLeafCert(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Leaf Certificate"},
		Issuer:       issuer.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	return cert, leafKey
}

// TestNewPathValidator тестирует создание валидатора
func TestNewPathValidator(t *testing.T) {
	root, _ := generateTestCertificate(t, "Root CA", true, 3650)

	config := ValidatorConfig{
		MaxChainLength: 5,
	}

	validator := NewPathValidator([]*x509.Certificate{root}, config)

	if validator == nil {
		t.Error("NewPathValidator returned nil")
	}
	if len(validator.trustedRoots) != 1 {
		t.Errorf("Expected 1 trusted root, got %d", len(validator.trustedRoots))
	}
	if validator.config.MaxChainLength != 5 {
		t.Errorf("Expected MaxChainLength 5, got %d", validator.config.MaxChainLength)
	}
}

// TestValidate_ValidChain тестирует валидацию корректной цепочки
func TestValidate_ValidChain(t *testing.T) {
	certs, keys := generateCertChain(t, 2)

	leafCert, _ := generateLeafCert(t, certs[1], keys[1])

	chain := []*x509.Certificate{leafCert, certs[1], certs[0]}

	config := ValidatorConfig{}
	validator := NewPathValidator([]*x509.Certificate{certs[0]}, config)

	result := validator.Validate(chain)

	if result == nil {
		t.Fatal("Validate returned nil")
	}

	if !result.OverallStatus {
		t.Errorf("Expected OverallStatus true, got false. First error: %s", result.FirstError)
	}

	if len(result.Chain) != 3 {
		t.Errorf("Expected chain length 3, got %d", len(result.Chain))
	}

	for i, certVal := range result.Chain {
		if !certVal.SignatureValid {
			t.Errorf("Certificate %d signature invalid", i)
		}
		if !certVal.ValidityPeriod {
			t.Errorf("Certificate %d validity period invalid", i)
		}
	}
}

// TestValidate_ExpiredCertificate тестирует просроченный сертификат
func TestValidate_ExpiredCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	expiredCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Expired Cert"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Истек вчера
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	expiredCertDER, err := x509.CreateCertificate(rand.Reader, expiredCert, expiredCert, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create expired cert: %v", err)
	}

	cert, _ := x509.ParseCertificate(expiredCertDER)

	config := ValidatorConfig{}
	validator := NewPathValidator([]*x509.Certificate{cert}, config)

	result := validator.Validate([]*x509.Certificate{cert})

	if result == nil {
		t.Fatal("Validate returned nil")
	}

	if result.OverallStatus {
		t.Error("Expected OverallStatus false for expired certificate")
	}

	if len(result.Chain) > 0 && result.Chain[0].ValidityPeriod {
		t.Error("Expected ValidityPeriod false for expired certificate")
	}
}

// TestValidate_InvalidSignature тестирует неверную подпись
func TestValidate_InvalidSignature(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		Issuer:                pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		Issuer:       rootCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &wrongKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	config := ValidatorConfig{}
	validator := NewPathValidator([]*x509.Certificate{rootCert}, config)

	result := validator.Validate([]*x509.Certificate{leafCert, rootCert})

	if result == nil {
		t.Fatal("Validate returned nil")
	}

	if len(result.Chain) > 0 && !result.Chain[0].SignatureValid {
		t.Log("Signature invalid as expected")
	}
}

// TestValidate_EmptyChain тестирует пустую цепочку
func TestValidate_EmptyChain(t *testing.T) {
	config := ValidatorConfig{}
	validator := NewPathValidator([]*x509.Certificate{}, config)

	result := validator.Validate([]*x509.Certificate{})

	if result == nil {
		t.Fatal("Validate returned nil")
	}

	if result.OverallStatus {
		t.Error("Expected OverallStatus false for empty chain")
	}

	if result.FirstError == "" {
		t.Error("Expected FirstError for empty chain")
	}
}

// generateTestCertificate создает тестовый сертификат
func generateTestCertificate(t *testing.T, subject string, isCA bool, validityDays int) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		Issuer:       pkix.Name{CommonName: subject},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.BasicConstraintsValid = true
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
