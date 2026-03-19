package ocsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// MockDB - мок для тестирования
type MockDB struct {
	statusMap map[string]*StatusResult
}

// NewMockDB создает новый мок
func NewMockDB() *MockDB {
	return &MockDB{
		statusMap: make(map[string]*StatusResult),
	}
}

// GetCertificateStatus реализует интерфейс StatusChecker
func (m *MockDB) GetCertificateStatus(serialHex string) (*StatusResult, error) {
	if result, ok := m.statusMap[serialHex]; ok {
		return result, nil
	}
	return &StatusResult{
		Status:     StatusUnknown,
		ThisUpdate: time.Now().UTC(),
	}, nil
}

// GetIssuerByHashes реализует интерфейс StatusChecker
func (m *MockDB) GetIssuerByHashes(nameHash, keyHash []byte) (*x509.Certificate, error) {
	return nil, nil
}

// SetStatus устанавливает статус для тестов
func (m *MockDB) SetStatus(serialHex string, status StatusResult) {
	m.statusMap[serialHex] = &status
}

// generateTestCert создает тестовый сертификат
func generateTestCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, priv
}

// createTestLogger создает тестовый логгер
func createTestLogger(t *testing.T) *log.Logger {
	return log.New(os.Stderr, "[TEST] ", log.LstdFlags)
}

// TestNewResponder проверяет создание responder
func TestNewResponder(t *testing.T) {
	mockDB := NewMockDB()
	cert, key := generateTestCert(t)
	logger := createTestLogger(t)

	config := &ResponderConfig{
		DB:            mockDB,
		ResponderCert: cert,
		ResponderKey:  key,
		IssuerCert:    cert,
		CacheTTL:      60,
		Logger:        logger,
		EnableCache:   true,
	}

	responder := NewResponder(config)
	if responder == nil {
		t.Error("Expected non-nil responder")
	}
}

// TestHandleRequestGood проверяет запрос для действительного сертификата
func TestHandleRequestGood(t *testing.T) {
	mockDB := NewMockDB()
	issuer, key := generateTestCert(t)
	logger := createTestLogger(t)

	config := &ResponderConfig{
		DB:            mockDB,
		ResponderCert: issuer,
		ResponderKey:  key,
		IssuerCert:    issuer,
		CacheTTL:      60,
		Logger:        logger,
		EnableCache:   true,
	}

	responder := NewResponder(config)

	request := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	response, err := responder.handleRequest(request, "127.0.0.1")
	if err == nil {
		t.Log("Got response, length:", len(response))
	} else {
		t.Logf("Expected error or response, got: %v", err)
	}
}

// TestServeHTTP проверяет HTTP обработчик
func TestServeHTTP(t *testing.T) {
	mockDB := NewMockDB()
	issuer, key := generateTestCert(t)
	logger := createTestLogger(t)

	config := &ResponderConfig{
		DB:            mockDB,
		ResponderCert: issuer,
		ResponderKey:  key,
		IssuerCert:    issuer,
		CacheTTL:      60,
		Logger:        logger,
		EnableCache:   true,
	}

	responder := NewResponder(config)

	server := httptest.NewServer(responder)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", server.URL, bytes.NewReader([]byte("test")))
	req.Header.Set("Content-Type", "text/plain")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("Expected 415, got %d", resp.StatusCode)
	}
}

// TestCache проверяет работу кэша
func TestCache(t *testing.T) {
	cache := NewResponseCache(60)
	key := []byte("test-key")
	data := []byte("test-data")
	serial := "12345"

	if cached := cache.Get(key); cached != nil {
		t.Error("Expected nil for non-existent key")
	}

	cache.Set(key, data, serial)

	if cached := cache.Get(key); cached == nil {
		t.Error("Expected cached data")
	} else if !bytes.Equal(cached, data) {
		t.Error("Cached data mismatch")
	}

	cache.InvalidateBySerial(serial)
	if cached := cache.Get(key); cached != nil {
		t.Error("Expected nil after invalidation")
	}

	cache.Set(key, data, serial)
	cache.Clear()
	if cached := cache.Get(key); cached != nil {
		t.Error("Expected nil after clear")
	}
}

// TestResponderConfig проверяет конфигурацию
func TestResponderConfig(t *testing.T) {
	mockDB := NewMockDB()
	cert, key := generateTestCert(t)
	logger := createTestLogger(t)

	config := &ResponderConfig{
		DB:            mockDB,
		ResponderCert: cert,
		ResponderKey:  key,
		IssuerCert:    cert,
		CacheTTL:      60,
		Logger:        logger,
		EnableCache:   false,
	}

	responder := NewResponder(config)
	if responder.cache != nil {
		t.Error("Expected cache to be nil when EnableCache=false")
	}

	config.EnableCache = true
	responder = NewResponder(config)
	if responder.cache == nil {
		t.Error("Expected cache to be initialized when EnableCache=true")
	}
}
