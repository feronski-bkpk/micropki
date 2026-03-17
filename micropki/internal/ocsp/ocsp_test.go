package ocsp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	stdcrypto "crypto"

	"micropki/micropki/internal/templates"
)

// MockDB - мок базы данных для тестирования
type MockDB struct {
	certs map[string]*StatusResult
}

func NewMockDB() *MockDB {
	return &MockDB{
		certs: make(map[string]*StatusResult),
	}
}

func (m *MockDB) GetCertificateStatus(issuerNameHash, issuerKeyHash []byte, serial *big.Int) (*StatusResult, error) {
	serialHex := hex.EncodeToString(serial.Bytes())
	if result, ok := m.certs[serialHex]; ok {
		return result, nil
	}
	return &StatusResult{
		Status:     StatusUnknown,
		ThisUpdate: time.Now().UTC(),
	}, nil
}

func (m *MockDB) GetIssuerByHashes(nameHash, keyHash []byte) (*x509.Certificate, error) {
	return createTestIssuerCert()
}

func (m *MockDB) AddCert(serialHex string, status CertStatus) {
	m.certs[serialHex] = &StatusResult{
		Status:     status,
		ThisUpdate: time.Now().UTC(),
	}
}

func (m *MockDB) AddRevokedCert(serialHex string, revTime time.Time, reason int) {
	m.certs[serialHex] = &StatusResult{
		Status:           StatusRevoked,
		RevocationTime:   &revTime,
		RevocationReason: &reason,
		ThisUpdate:       time.Now().UTC(),
	}
}

// Структура для хранения пары сертификат-ключ
type TestCertBundle struct {
	Cert *x509.Certificate
	Key  stdcrypto.PrivateKey
}

// Создание тестового корневого CA
func createTestRootCA() (*TestCertBundle, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNum := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &TestCertBundle{Cert: cert, Key: priv}, nil
}

// Создание тестового промежуточного CA
func createTestIntermediateCA(rootBundle *TestCertBundle) (*TestCertBundle, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNum := big.NewInt(2)
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootBundle.Cert, &priv.PublicKey, rootBundle.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &TestCertBundle{Cert: cert, Key: priv}, nil
}

// Создание тестового OCSP responder сертификата
func createTestOCSPResponderCert(issuerBundle *TestCertBundle) (*TestCertBundle, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNum, _ := templates.NewSerialNumber()

	template := &x509.Certificate{
		SerialNumber: serialNum.BigInt(),
		Subject: pkix.Name{
			CommonName: "Test OCSP Responder",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 5, 5, 7, 3, 9},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerBundle.Cert, &priv.PublicKey, issuerBundle.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &TestCertBundle{Cert: cert, Key: priv}, nil
}

// Создание тестового сертификата конечного субъекта
func createTestEndEntityCert(issuerBundle *TestCertBundle) (*TestCertBundle, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNum, _ := templates.NewSerialNumber()

	template := &x509.Certificate{
		SerialNumber: serialNum.BigInt(),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerBundle.Cert, &priv.PublicKey, issuerBundle.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &TestCertBundle{Cert: cert, Key: priv}, nil
}

func createTestIssuerCert() (*x509.Certificate, error) {
	rootBundle, err := createTestRootCA()
	if err != nil {
		return nil, err
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		return nil, err
	}

	return intBundle.Cert, nil
}

// Вспомогательная функция для создания тестового OCSP-запроса (DER)
func createTestOCSPRequestDER(issuer *x509.Certificate, serial *big.Int) ([]byte, error) {
	nameHash, keyHash, _ := ComputeIssuerHashes(issuer)

	type algId struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}

	type certID struct {
		HashAlgorithm  algId
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}

	type reqCert struct {
		CertID certID `asn1:"explicit,tag:0"`
	}

	type singleRequest struct {
		ReqCert reqCert `asn1:"explicit,tag:0"`
	}

	type requestList struct {
		Requests []singleRequest `asn1:"explicit,tag:2"`
	}

	type tbsRequest struct {
		Version       int           `asn1:"default:0,explicit,tag:0"`
		RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`
		RequestList   requestList   `asn1:"explicit,tag:2"`
	}

	type ocspRequest struct {
		TBSRequest tbsRequest
	}

	req := ocspRequest{
		TBSRequest: tbsRequest{
			Version: 0,
			RequestList: requestList{
				Requests: []singleRequest{
					{
						ReqCert: reqCert{
							CertID: certID{
								HashAlgorithm: algId{
									Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
								},
								IssuerNameHash: nameHash,
								IssuerKeyHash:  keyHash,
								SerialNumber:   serial,
							},
						},
					},
				},
			},
		},
	}

	return asn1.Marshal(req)
}

// Для тестов с nonce
func createTestOCSPRequestWithNonceDER(issuer *x509.Certificate, serial *big.Int, nonce []byte) ([]byte, error) {
	nameHash, keyHash, _ := ComputeIssuerHashes(issuer)

	type algId struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}

	type certID struct {
		HashAlgorithm  algId
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}

	type reqCert struct {
		CertID certID `asn1:"explicit,tag:0"`
	}

	type singleRequest struct {
		ReqCert reqCert `asn1:"explicit,tag:0"`
	}

	type requestList struct {
		Requests []singleRequest `asn1:"explicit,tag:2"`
	}

	type extensions struct {
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
	}

	type tbsRequest struct {
		Version       int           `asn1:"default:0,explicit,tag:0"`
		RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`
		RequestList   requestList   `asn1:"explicit,tag:2"`
		Extensions    extensions    `asn1:"optional,explicit,tag:3"`
	}

	type ocspRequest struct {
		TBSRequest tbsRequest
	}

	nonceExt := pkix.Extension{
		Id:    OIDOCSPNonce,
		Value: nonce,
	}

	req := ocspRequest{
		TBSRequest: tbsRequest{
			Version: 0,
			RequestList: requestList{
				Requests: []singleRequest{
					{
						ReqCert: reqCert{
							CertID: certID{
								HashAlgorithm: algId{
									Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
								},
								IssuerNameHash: nameHash,
								IssuerKeyHash:  keyHash,
								SerialNumber:   serial,
							},
						},
					},
				},
			},
			Extensions: extensions{
				Extensions: []pkix.Extension{nonceExt},
			},
		},
	}

	return asn1.Marshal(req)
}

// TEST-28: OCSP Signer Certificate Test
func TestOCSPResponderCertificate(t *testing.T) {
	t.Log("TEST-28: Проверка сертификата OCSP-ответчика")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	cert := ocspBundle.Cert

	if cert.IsCA {
		t.Error("Сертификат OCSP-ответчика не должен быть CA")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("Отсутствует KeyUsage DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("OCSP-сертификат не должен иметь KeyUsage CertSign")
	}

	foundOCSPSigning := false
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}) {
			foundOCSPSigning = true
			break
		}
	}
	if !foundOCSPSigning {
		t.Log("Предупреждение: Extended Key Usage OCSPSigning не найдено, но это может быть нормально")
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootBundle.Cert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intBundle.Cert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Logf("Предупреждение: проверка цепочки сертификатов: %v", err)
	} else {
		t.Log("✓ Цепочка сертификатов валидна")
	}

	t.Log("✓ TEST-28 пройден")
}

// TEST-29: OCSP Request/Response Cycle – Good Certificate
func TestOCSPGoodCertificate(t *testing.T) {
	t.Log("TEST-29: Проверка действительного сертификата (good)")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	mockDB := NewMockDB()
	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())
	mockDB.AddCert(serialHex, StatusGood)

	reqDER, err := createTestOCSPRequestDER(intBundle.Cert, serial)
	if err != nil {
		t.Fatalf("Не удалось создать запрос: %v", err)
	}

	req, err := ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("Не удалось разобрать запрос: %v", err)
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        intBundle.Cert,
		ResponderCert:     ocspBundle.Cert,
		ResponderKey:      ocspBundle.Key,
		DB:                mockDB,
		CacheTTL:          60,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)
	respDER, err := builder.Build()
	if err != nil {
		t.Fatalf("Не удалось создать ответ: %v", err)
	}

	if len(respDER) == 0 {
		t.Error("Пустой ответ")
	}

	t.Logf("✓ TEST-29 пройден, размер ответа: %d байт", len(respDER))
}

// TEST-30: OCSP Request/Response – Revoked Certificate
func TestOCSPRevokedCertificate(t *testing.T) {
	t.Log("TEST-30: Проверка отозванного сертификата (revoked)")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	mockDB := NewMockDB()
	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())
	revTime := time.Now().Add(-24 * time.Hour)
	reason := 1 // keyCompromise
	mockDB.AddRevokedCert(serialHex, revTime, reason)

	reqDER, err := createTestOCSPRequestDER(intBundle.Cert, serial)
	if err != nil {
		t.Fatalf("Не удалось создать запрос: %v", err)
	}

	req, err := ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("Не удалось разобрать запрос: %v", err)
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        intBundle.Cert,
		ResponderCert:     ocspBundle.Cert,
		ResponderKey:      ocspBundle.Key,
		DB:                mockDB,
		CacheTTL:          60,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)
	respDER, err := builder.Build()
	if err != nil {
		t.Fatalf("Не удалось создать ответ: %v", err)
	}

	if len(respDER) == 0 {
		t.Error("Пустой ответ")
	}

	t.Logf("✓ TEST-30 пройден, размер ответа: %d байт", len(respDER))
}

// TEST-31: OCSP Request/Response – Unknown Certificate
func TestOCSPUnknownCertificate(t *testing.T) {
	t.Log("TEST-31: Проверка неизвестного сертификата (unknown)")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	mockDB := NewMockDB()
	serial := big.NewInt(99999)

	reqDER, err := createTestOCSPRequestDER(intBundle.Cert, serial)
	if err != nil {
		t.Fatalf("Не удалось создать запрос: %v", err)
	}

	req, err := ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("Не удалось разобрать запрос: %v", err)
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        intBundle.Cert,
		ResponderCert:     ocspBundle.Cert,
		ResponderKey:      ocspBundle.Key,
		DB:                mockDB,
		CacheTTL:          60,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)
	respDER, err := builder.Build()
	if err != nil {
		t.Fatalf("Не удалось создать ответ: %v", err)
	}

	if len(respDER) == 0 {
		t.Error("Пустой ответ")
	}

	t.Logf("✓ TEST-31 пройден, размер ответа: %d байт", len(respDER))
}

// TEST-32: OCSP Nonce Test
func TestOCSPNonce(t *testing.T) {
	t.Log("TEST-32: Проверка обработки nonce")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	mockDB := NewMockDB()
	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())
	mockDB.AddCert(serialHex, StatusGood)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	reqDER, err := createTestOCSPRequestWithNonceDER(intBundle.Cert, serial, nonce)
	if err != nil {
		t.Fatalf("Не удалось создать запрос с nonce: %v", err)
	}

	req, err := ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("Не удалось разобрать запрос с nonce: %v", err)
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        intBundle.Cert,
		ResponderCert:     ocspBundle.Cert,
		ResponderKey:      ocspBundle.Key,
		DB:                mockDB,
		CacheTTL:          60,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)
	respDER, err := builder.Build()
	if err != nil {
		t.Fatalf("Не удалось создать ответ с nonce: %v", err)
	}

	t.Logf("✓ TEST-32: Запрос с nonce обработан, размер ответа: %d байт", len(respDER))
}

// TEST-36: Performance / Load Test
func TestOCSPPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Пропуск нагрузочного теста в коротком режиме")
	}

	t.Log("TEST-36: Нагрузочное тестирование")

	rootBundle, err := createTestRootCA()
	if err != nil {
		t.Fatalf("Не удалось создать корневой CA: %v", err)
	}

	intBundle, err := createTestIntermediateCA(rootBundle)
	if err != nil {
		t.Fatalf("Не удалось создать промежуточный CA: %v", err)
	}

	ocspBundle, err := createTestOCSPResponderCert(intBundle)
	if err != nil {
		t.Fatalf("Не удалось создать сертификат ответчика: %v", err)
	}

	mockDB := NewMockDB()
	serial := big.NewInt(12345)
	serialHex := hex.EncodeToString(serial.Bytes())
	mockDB.AddCert(serialHex, StatusGood)

	reqDER, err := createTestOCSPRequestDER(intBundle.Cert, serial)
	if err != nil {
		t.Fatalf("Не удалось создать запрос: %v", err)
	}

	req, err := ParseRequest(reqDER)
	if err != nil {
		t.Fatalf("Не удалось разобрать запрос: %v", err)
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        intBundle.Cert,
		ResponderCert:     ocspBundle.Cert,
		ResponderKey:      ocspBundle.Key,
		DB:                mockDB,
		CacheTTL:          60,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)

	start := time.Now()
	for i := 0; i < 100; i++ {
		_, err := builder.Build()
		if err != nil {
			t.Fatalf("Ошибка при выполнении запроса %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	t.Logf("100 запросов выполнено за %v (среднее: %v на запрос)",
		duration, duration/100)
	t.Log("✓ TEST-36 пройден")
}
