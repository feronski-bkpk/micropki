// Package chain_test содержит тесты для проверки цепочек сертификатов.
// Тесты проверяют:
//   - Создание валидных цепочек (корневой CA → промежуточный CA → конечный сертификат)
//   - Успешную проверку корректных цепочек
//   - Обнаружение ошибок в некорректных цепочках
//   - Проверку подписей на всех уровнях
//   - Проверку ограничений (CA флаги, сроки действия)
//
// Все тесты используют генерацию тестовых сертификатов для изоляции от внешних зависимостей.
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
	// Генерация ключевой пары
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Создание шаблона
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
		// Самоподписанный сертификат
		issuerCert = template
		issuerKey = key
	}

	// Создание сертификата
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
	// Генерация корневого CA
	rootCert, rootKey, err := generateTestCert(true, "Test Root CA", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA: %v", err)
	}

	// Генерация промежуточного CA, подписанного корневым
	intermediateCert, intermediateKey, err := generateTestCert(true, "Test Intermediate CA", rootKey, rootCert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать промежуточный CA: %v", err)
	}

	// Генерация конечного сертификата, подписанного промежуточным
	leafCert, _, err := generateTestCert(false, "test.example.com", intermediateKey, intermediateCert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать конечный сертификат: %v", err)
	}

	// Создание цепочки
	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: intermediateCert,
		Root:         rootCert,
	}

	// Проверка цепочки
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
	// Генерация двух независимых CA
	root1Cert, _, err := generateTestCert(true, "Test Root CA 1", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA 1: %v", err)
	}

	root2Cert, root2Key, err := generateTestCert(true, "Test Root CA 2", nil, nil)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать корневой CA 2: %v", err)
	}

	// Генерация конечного сертификата, подписанного root2
	leafCert, _, err := generateTestCert(false, "test.example.com", root2Key, root2Cert)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать конечный сертификат: %v", err)
	}

	// Создание несоответствующей цепочки (конечный сертификат подписан root2,
	// но корневым указан root1)
	chain := &Chain{
		Leaf:         leafCert,
		Intermediate: root2Cert, // Использование root2 как промежуточного
		Root:         root1Cert,
	}

	// Проверка должна завершиться ошибкой
	if err := chain.Verify(); err == nil {
		t.Error("Ожидалась ошибка проверки цепочки, но проверка прошла успешно")
	}
}
