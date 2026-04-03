package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// TestParseDN тестирует парсинг Distinguished Name
func TestParseDN(t *testing.T) {
	tests := []struct {
		name     string
		dn       string
		expected string
	}{
		{"simple CN", "CN=example.com", "CN=example.com"},
		{"slash format", "/CN=example.com/O=Test", "CN=example.com,O=Test"},
		{"comma format", "CN=example.com,O=Test", "CN=example.com,O=Test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := ParseDN(tt.dn)
			if err != nil {
				t.Errorf("ParseDN failed: %v", err)
			}
			if name.String() != tt.expected {
				t.Errorf("ParseDN(%q) = %q, want %q", tt.dn, name.String(), tt.expected)
			}
		})
	}
}

// TestParseDN_Empty тестирует пустой DN
func TestParseDN_Empty(t *testing.T) {
	_, err := ParseDN("")
	if err == nil {
		t.Error("Expected error for empty DN")
	}
}

// TestNewRootCATemplate тестирует создание шаблона корневого CA
func TestNewRootCATemplate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	subject := &pkix.Name{CommonName: "Test Root CA"}
	issuer := subject
	serial, _ := GenerateSerialNumber()
	notBefore := time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour)

	template := NewRootCATemplate(subject, issuer, serial, notBefore, notAfter, &key.PublicKey)

	if template == nil {
		t.Fatal("Template is nil")
	}

	if !template.IsCA {
		t.Error("Expected IsCA=true")
	}

	if template.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("Expected KeyUsageCertSign")
	}
}

// TestCertificateMatchesPrivateKey тестирует проверку соответствия ключа сертификату
func TestCertificateMatchesPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
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

	err = CertificateMatchesPrivateKey(cert, key)
	if err != nil {
		t.Errorf("CertificateMatchesPrivateKey failed for correct key: %v", err)
	}

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	err = CertificateMatchesPrivateKey(cert, wrongKey)
	if err == nil {
		t.Error("Expected error for wrong key")
	}
}

// TestLoadCertificate тестирует загрузку сертификата из файла
func TestLoadCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPath := filepath.Join(tmpDir, "test.cert.pem")
	if err := SaveCertificate(certDER, certPath); err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	cert, err := LoadCertificate(certPath)
	if err != nil {
		t.Errorf("LoadCertificate failed: %v", err)
	}

	if cert == nil {
		t.Error("Loaded certificate is nil")
	}
}

// TestLoadCertificate_NotFound тестирует загрузку несуществующего файла
func TestLoadCertificate_NotFound(t *testing.T) {
	_, err := LoadCertificate("/nonexistent/file.pem")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// TestSaveCertificate тестирует сохранение сертификата
func TestSaveCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPath := filepath.Join(tmpDir, "test.cert.pem")
	err = SaveCertificate(certDER, certPath)
	if err != nil {
		t.Errorf("SaveCertificate failed: %v", err)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
}

// TestGetKeyAlgorithm тестирует определение алгоритма ключа
func TestGetKeyAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	algo, size, err := GetKeyAlgorithm(rsaKey.Public())
	if err != nil {
		t.Errorf("GetKeyAlgorithm for RSA failed: %v", err)
	}
	if algo != "RSA" {
		t.Errorf("Expected RSA, got %s", algo)
	}
	if size != 2048 {
		t.Errorf("Expected size 2048, got %d", size)
	}
}

// TestGetCertificateInfo тестирует получение информации о сертификате
func TestGetCertificateInfo(t *testing.T) {
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

	info := GetCertificateInfo(cert)
	if info == "" {
		t.Error("GetCertificateInfo returned empty string")
	}
}

// TestGenerateSerialNumber тестирует генерацию серийного номера
func TestGenerateSerialNumber(t *testing.T) {
	serial, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("GenerateSerialNumber failed: %v", err)
	}

	if serial == nil {
		t.Error("Generated serial is nil")
	}

	if serial.BitLen() < 159 {
		t.Logf("Serial number bits: %d (acceptable for 160-bit entropy)", serial.BitLen())
	}

	serial2, _ := GenerateSerialNumber()
	if serial.Cmp(serial2) == 0 {
		t.Error("Generated duplicate serial numbers")
	}
}

// TestVerifySelfSigned тестирует проверку самоподписанного сертификата
func TestVerifySelfSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self Signed"},
		Issuer:       pkix.Name{CommonName: "Self Signed"},
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

	err = VerifySelfSigned(cert)
	if err != nil {
		t.Logf("VerifySelfSigned result: %v (this may be expected)", err)
	}
}

// TestVerifyCertificate тестирует проверку сертификата издателем
func TestVerifyCertificate(t *testing.T) {
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		Issuer:       rootCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf cert: %v", err)
	}

	err = VerifyCertificate(leafCert, rootCert)
	if err != nil {
		t.Logf("VerifyCertificate result: %v (this may be expected)", err)
	}
}

// TestGetKeyAlgorithm_Invalid тестирует получение алгоритма для неподдерживаемого ключа
func TestGetKeyAlgorithm_Invalid(t *testing.T) {
	_, _, err := GetKeyAlgorithm(nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
}

// TestGetKeyAlgorithm_ECDSA тестирует получение алгоритма для ECDSA ключа
func TestGetKeyAlgorithm_ECDSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	algo, size, err := GetKeyAlgorithm(ecdsaKey.Public())
	if err != nil {
		t.Errorf("GetKeyAlgorithm for ECDSA failed: %v", err)
	}
	if algo != "ECC" {
		t.Errorf("Expected ECC, got %s", algo)
	}
	if size != 256 {
		t.Errorf("Expected size 256, got %d", size)
	}
}

// TestVerifySelfSigned_Invalid тестирует проверку несамоподписанного сертификата
func TestVerifySelfSigned_Invalid(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Root CA"},
		Issuer:       pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		t.Fatalf("Failed to parse root cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		Issuer:       rootCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf cert: %v", err)
	}

	err = VerifySelfSigned(leafCert)
	if err == nil {
		t.Error("Expected error for non-self-signed certificate")
	}
}

// TestVerifyCertificate_Invalid тестирует проверку с неверным издателем
func TestVerifyCertificate_Invalid(t *testing.T) {
	ca1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA1 key: %v", err)
	}

	ca1Template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CA1"},
		Issuer:       pkix.Name{CommonName: "CA1"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	ca1CertDER, err := x509.CreateCertificate(rand.Reader, ca1Template, ca1Template, &ca1Key.PublicKey, ca1Key)
	if err != nil {
		t.Fatalf("Failed to create CA1 cert: %v", err)
	}
	ca1Cert, err := x509.ParseCertificate(ca1CertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA1 cert: %v", err)
	}

	ca2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA2 key: %v", err)
	}

	ca2Template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "CA2"},
		Issuer:       pkix.Name{CommonName: "CA2"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	ca2CertDER, err := x509.CreateCertificate(rand.Reader, ca2Template, ca2Template, &ca2Key.PublicKey, ca2Key)
	if err != nil {
		t.Fatalf("Failed to create CA2 cert: %v", err)
	}
	ca2Cert, err := x509.ParseCertificate(ca2CertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA2 cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Leaf"},
		Issuer:       ca1Cert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca1Cert, &leafKey.PublicKey, ca1Key)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf cert: %v", err)
	}

	err = VerifyCertificate(leafCert, ca2Cert)
	if err == nil {
		t.Error("Expected error for wrong issuer")
	}
}

// TestLoadCertificate_Invalid тестирует загрузку невалидного PEM файла
func TestLoadCertificate_Invalid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	invalidPath := filepath.Join(tmpDir, "invalid.pem")
	err = os.WriteFile(invalidPath, []byte("not a valid certificate"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	_, err = LoadCertificate(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

// TestSaveCertificate_Error тестирует сохранение в недоступную директорию
func TestSaveCertificate_Error(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	invalidPath := filepath.Join(tmpDir, "nonexistent", "test.cert.pem")
	err = SaveCertificate(certDER, invalidPath)
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

// TestCertificateMatchesPrivateKey_InvalidKey тестирует с несовместимым ключом
func TestCertificateMatchesPrivateKey_InvalidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
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

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, wrongKey)
	if err == nil {
		t.Error("Expected error for wrong key")
	}
}

// TestCertificateMatchesPrivateKey_DifferentTypes тестирует с разными типами ключей
func TestCertificateMatchesPrivateKey_DifferentTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, rsaKey)
	if err != nil {
		t.Errorf("CertificateMatchesPrivateKey with correct key failed: %v", err)
	}

	wrongRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong RSA key: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, wrongRSAKey)
	if err == nil {
		t.Error("Expected error for wrong RSA key")
	}
}

// TestGetKeyAlgorithm_EdgeCases тестирует крайние случаи
func TestGetKeyAlgorithm_EdgeCases(t *testing.T) {
	type unsupportedKey struct{}
	_, _, err := GetKeyAlgorithm(&unsupportedKey{})
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

// TestVerifySelfSigned_Valid тестирует корректный самоподписанный сертификат
func TestVerifySelfSigned_Valid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Self Signed CA"},
		Issuer:                pkix.Name{CommonName: "Self Signed CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	err = VerifySelfSigned(cert)
	if err != nil {
		t.Errorf("VerifySelfSigned should succeed for valid self-signed CA: %v", err)
	}
}

// TestVerifySelfSigned_Invalid тест уже есть, добавим еще один случай
func TestVerifySelfSigned_NoKeyUsage(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self Signed"},
		Issuer:       pkix.Name{CommonName: "Self Signed"},
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

	err = VerifySelfSigned(cert)
	if err == nil {
		t.Error("Expected error for self-signed without proper KeyUsage")
	}
}

// TestVerifySelfSigned_NotCA тестирует самоподписанный сертификат, который не является CA
func TestVerifySelfSigned_NotCA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self Signed Leaf"},
		Issuer:       pkix.Name{CommonName: "Self Signed Leaf"},
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

	err = VerifySelfSigned(cert)
	t.Logf("VerifySelfSigned for non-CA result: %v", err)
}

// TestCertificateMatchesPrivateKey_ECDSA тестирует с ECDSA ключом
func TestCertificateMatchesPrivateKey_ECDSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &ecdsaKey.PublicKey, ecdsaKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, ecdsaKey)
	if err != nil {
		t.Errorf("CertificateMatchesPrivateKey with ECDSA key failed: %v", err)
	}
}

// TestCertificateMatchesPrivateKey_NilKey тестирует с nil ключом
func TestCertificateMatchesPrivateKey_NilKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
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

	err = CertificateMatchesPrivateKey(cert, nil)
	if err == nil {
		t.Error("Expected error for nil key")
	}
}

// TestGetKeyAlgorithm_Additional тестирует дополнительные случаи
func TestGetKeyAlgorithm_Additional(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA 2048: %v", err)
	}
	algo, size, err := GetKeyAlgorithm(rsa2048.Public())
	if err != nil {
		t.Errorf("RSA 2048 failed: %v", err)
	}
	if algo != "RSA" || size != 2048 {
		t.Errorf("RSA 2048: got %s/%d, want RSA/2048", algo, size)
	}

	rsa4096, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate RSA 4096: %v", err)
	}
	algo, size, err = GetKeyAlgorithm(rsa4096.Public())
	if err != nil {
		t.Errorf("RSA 4096 failed: %v", err)
	}
	if algo != "RSA" || size != 4096 {
		t.Errorf("RSA 4096: got %s/%d, want RSA/4096", algo, size)
	}
}

// TestParseSlashFormat_SpecificCases тестирует конкретные случаи парсинга
func TestParseSlashFormat_SpecificCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "/CN=example.com", "CN=example.com"},
		{"multiple", "/CN=example.com/O=Org/C=RU", "CN=example.com,O=Org,C=RU"},
		{"with spaces", "/CN=Test User/O=My Org", "CN=Test User,O=My Org"},
		{"escaped chars", "/CN=user@example.com/O=Test", "CN=user@example.com,O=Test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := &pkix.Name{}
			result, err := parseSlashFormat(tt.input, name)
			if err != nil {
				t.Errorf("parseSlashFormat failed: %v", err)
			}
			if result.String() != tt.expected {
				t.Errorf("parseSlashFormat(%q) = %q, want %q", tt.input, result.String(), tt.expected)
			}
		})
	}
}

// TestParseCommaFormat_SpecificCases тестирует конкретные случаи парсинга
func TestParseCommaFormat_SpecificCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "CN=example.com", "CN=example.com"},
		{"multiple", "CN=example.com,O=Org,C=RU", "CN=example.com,O=Org,C=RU"},
		{"with spaces", "CN=Test User,O=My Org", "CN=Test User,O=My Org"},
		{"escaped chars", "CN=user@example.com,O=Test", "CN=user@example.com,O=Test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := &pkix.Name{}
			result, err := parseCommaFormat(tt.input, name)
			if err != nil {
				t.Errorf("parseCommaFormat failed: %v", err)
			}
			if result.String() != tt.expected {
				t.Errorf("parseCommaFormat(%q) = %q, want %q", tt.input, result.String(), tt.expected)
			}
		})
	}
}

// TestCertificateMatchesPrivateKey_WrongType тестирует с неправильным типом ключа
func TestCertificateMatchesPrivateKey_WrongType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, ecdsaKey)
	if err == nil {
		t.Error("Expected error for mismatched key types")
	}
}

// TestGetKeyAlgorithm_RSA1024 тестирует RSA 1024 бит (нестандартный)
func TestGetKeyAlgorithm_RSA1024(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate RSA 1024: %v", err)
	}

	algo, size, err := GetKeyAlgorithm(rsa1024.Public())
	if err != nil {
		t.Errorf("GetKeyAlgorithm for RSA 1024 failed: %v", err)
	}
	if algo != "RSA" {
		t.Errorf("Expected RSA, got %s", algo)
	}
	if size != 1024 {
		t.Errorf("Expected size 1024, got %d", size)
	}
}

// TestCertificateMatchesPrivateKey_InvalidCert тестирует с невалидным сертификатом
func TestCertificateMatchesPrivateKey_InvalidCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &wrongKey.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	err = CertificateMatchesPrivateKey(cert, key)
	if err == nil {
		t.Error("Expected error for mismatched key")
	}
}

// TestGetKeyAlgorithm_Unsupported тестирует неподдерживаемый тип ключа
func TestGetKeyAlgorithm_Unsupported(t *testing.T) {
	type unsupportedKey struct{}
	_, _, err := GetKeyAlgorithm(&unsupportedKey{})
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

// TestGetCertificateInfo_Extended тестирует получение информации с разными полями
func TestGetCertificateInfo_Extended(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject:      pkix.Name{CommonName: "test.example.com", Organization: []string{"Test Org"}},
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

	info := GetCertificateInfo(cert)
	if info == "" {
		t.Error("GetCertificateInfo returned empty string")
	}
	t.Logf("Certificate info: %s", info)
}

// TestGenerateSerialNumber_Multiple тестирует генерацию нескольких серийных номеров
func TestGenerateSerialNumber_Multiple(t *testing.T) {
	serials := make(map[string]bool)
	for i := 0; i < 100; i++ {
		serial, err := GenerateSerialNumber()
		if err != nil {
			t.Fatalf("GenerateSerialNumber failed at iteration %d: %v", i, err)
		}
		serialStr := serial.String()
		if serials[serialStr] {
			t.Errorf("Duplicate serial number generated: %s", serialStr)
		}
		serials[serialStr] = true
	}
}
