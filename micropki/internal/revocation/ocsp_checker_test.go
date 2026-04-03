package revocation

import (
	"testing"
)

// TestNewOCSPChecker тестирует создание OCSP проверяльщика
func TestNewOCSPChecker(t *testing.T) {
	config := RevocationCheckerConfig{}
	checker := NewOCSPChecker(config)

	if checker == nil {
		t.Error("NewOCSPChecker returned nil")
	}
	if checker.client == nil {
		t.Error("HTTP client is nil")
	}
}

// TestCheck_NoOCSPURL тестирует проверку без OCSP URL
func TestCheck_NoOCSPURL(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test.example.com")
	issuer, _ := generateTestCertificate(t, "Issuer CA")

	config := RevocationCheckerConfig{}
	checker := NewOCSPChecker(config)

	result := checker.Check(cert, issuer)

	if result == nil {
		t.Fatal("Check returned nil")
	}

	if result.Status != StatusUnknown {
		t.Errorf("Expected StatusUnknown, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected error message")
	}
}

// TestOCSPChecker_ClearCache тестирует очистку кэша
func TestOCSPChecker_ClearCache(t *testing.T) {
	config := RevocationCheckerConfig{}
	checker := NewOCSPChecker(config)

	checker.cache["test"] = &OCSPCacheEntry{
		result: &RevocationResult{Status: StatusGood},
	}

	if len(checker.cache) == 0 {
		t.Skip("Cache is empty")
	}

	checker.ClearCache()

	if len(checker.cache) != 0 {
		t.Errorf("Expected empty cache after ClearCache, got %d entries", len(checker.cache))
	}
}

// TestMapOCSPReason тестирует преобразование кодов причин
func TestMapOCSPReason(t *testing.T) {
	tests := []struct {
		reason   int
		expected string
	}{
		{0, "unspecified"},
		{1, "keyCompromise"},
		{2, "cACompromise"},
		{3, "affiliationChanged"},
		{4, "superseded"},
		{5, "cessationOfOperation"},
		{6, "certificateHold"},
		{8, "removeFromCRL"},
		{9, "privilegeWithdrawn"},
		{10, "aACompromise"},
		{99, "unknown"},
	}

	for _, tt := range tests {
		result := mapOCSPReason(tt.reason)
		if result != tt.expected {
			t.Errorf("mapOCSPReason(%d) = %q, want %q", tt.reason, result, tt.expected)
		}
	}
}
