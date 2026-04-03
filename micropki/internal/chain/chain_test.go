// Package chain_test содержит тесты для проверки цепочек сертификатов.
package chain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCert создаёт тестовый сертификат для использования в тестах.
// Позволяет создавать как самоподписанные сертификаты, так и подписанные указанным издателем.
//
// Параметры:
//   - isCA: флаг, указывающий, является ли сертификат центром сертификации
//   - commonName: общее имя (CN) субъекта
//   - signingKey: закрытый ключ издателя (nil для самоподписанного)
//   - signingCert: сертификат издателя (nil для самоподписанного)
//
// Возвращает:
//   - *x509.Certificate: созданный сертификат
//   - *rsa.PrivateKey: закрытый ключ сертификата
//   - error: ошибку, если создание не удалось
func generateTestCert(isCA bool, commonName string, signingKey *rsa.PrivateKey, signingCert *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

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
		issuerCert = template
		issuerKey = key
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	return cert, key, err
}

// TestChainVerification проверяет успешную валидацию корректной цепочки.
// Создаёт:
//  1. Корневой CA (самоподписанный)
//  2. Промежуточный CA (подписанный корневым)
//  3. Конечный сертификат (подписанный промежуточным)
//
// Ожидает, что проверка цепочки завершится без ошибок.
func TestChainVerification(t *testing.T) {
	rootCert, rootKey, err := generateTestCert(true, "Test Root CA", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA: %v", err)
	}

	intermediateCert, intermediateKey, err := generateTestCert(true, "Test Intermediate CA", rootKey, rootCert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать промежуточный CA: %v", err)
	}

	leafCert, _, err := generateTestCert(false, "test.example.com", intermediateKey, intermediateCert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать конечный сертификат: %v", err)
	}

	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: intermediateCert,
		Root:         rootCert,
	}

	if err := chain.Verify(); err != nil {
		t.Errorf("Проверка цепочки не пройдена: %v", err)
	}
}

// TestInvalidChain проверяет, что некорректная цепочка обнаруживается.
// Создаёт два независимых CA и пытается построить цепочку с несоответствующим
// корневым сертификатом.
//
// Ожидает, что проверка цепочки завершится с ошибкой.
func TestInvalidChain(t *testing.T) {
	root1Cert, _, err := generateTestCert(true, "Test Root CA 1", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA 1: %v", err)
	}

	root2Cert, root2Key, err := generateTestCert(true, "Test Root CA 2", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA 2: %v", err)
	}

	leafCert, _, err := generateTestCert(false, "test.example.com", root2Key, root2Cert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать конечный сертификат: %v", err)
	}

	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: root2Cert,
		Root:         root1Cert,
	}

	if err := chain.Verify(); err == nil {
		t.Error("Ожидалась ошибка проверки цепочки, но проверка прошла успешно")
	}
}

// TestLoadCertificate тестирует загрузку отдельного сертификата
func TestLoadCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "chain_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cert, _, err := generateTestCert(true, "Test Cert", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate cert: %v", err)
	}

	certPath := filepath.Join(tmpDir, "test.crt")
	if err := saveCertToFile(cert, certPath); err != nil {
		t.Fatalf("Failed to save cert: %v", err)
	}

	loadedCert, err := LoadCertificate(certPath)
	if err != nil {
		t.Errorf("LoadCertificate failed: %v", err)
	}
	if loadedCert == nil {
		t.Error("Loaded certificate is nil")
	}
}

// saveCertToFile сохраняет сертификат в файл
func saveCertToFile(cert *x509.Certificate, path string) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return os.WriteFile(path, pemBytes, 0644)
}

// TestLoadChain тестирует загрузку цепочки из файлов
func TestLoadChain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "chain_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rootCert, rootKey, err := generateTestCert(true, "Root CA", nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate root cert: %v", err)
	}

	interCert, _, err := generateTestCert(true, "Intermediate CA", rootKey, rootCert)
	if err != nil {
		t.Fatalf("Failed to generate intermediate cert: %v", err)
	}

	leafCert, _, err := generateTestCert(false, "Leaf Cert", rootKey, rootCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	rootPath := filepath.Join(tmpDir, "root.crt")
	interPath := filepath.Join(tmpDir, "inter.crt")
	leafPath := filepath.Join(tmpDir, "leaf.crt")

	if err := saveCertToFile(rootCert, rootPath); err != nil {
		t.Fatalf("Failed to save root cert: %v", err)
	}
	if err := saveCertToFile(interCert, interPath); err != nil {
		t.Fatalf("Failed to save inter cert: %v", err)
	}
	if err := saveCertToFile(leafCert, leafPath); err != nil {
		t.Fatalf("Failed to save leaf cert: %v", err)
	}

	chain, err := LoadChain(leafPath, interPath, rootPath)
	if err != nil {
		t.Errorf("LoadChain failed: %v", err)
	}
	if chain == nil {
		t.Error("Loaded chain is nil")
	}
	if chain.Leaf == nil || chain.Intermediate == nil || chain.Root == nil {
		t.Error("Expected all chain components (Leaf, Intermediate, Root) to be non-nil")
	}
}
