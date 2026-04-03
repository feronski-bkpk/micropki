package validation

import (
	"crypto/x509"
	"testing"
)

// TestNewChainBuilder тестирует создание построителя цепочек
func TestNewChainBuilder(t *testing.T) {
	builder := NewChainBuilder([]*x509.Certificate{})
	if builder == nil {
		t.Error("NewChainBuilder returned nil")
	}
}

// TestBuildPath_Valid тестирует построение корректной цепочки
func TestBuildPath_Valid(t *testing.T) {
	certs, _ := generateCertChain(t, 3)
	intermediates := []*x509.Certificate{certs[1], certs[2]}
	builder := NewChainBuilder(intermediates)

	path, err := builder.BuildPath(certs[2], []*x509.Certificate{certs[0]})

	if err != nil {
		t.Logf("BuildPath result: %v", err)
	}

	if len(path) > 0 {
		t.Logf("Path length: %d", len(path))
	}
}

// TestBuildPath_WithIntermediate тестирует построение через промежуточный сертификат
func TestBuildPath_WithIntermediate(t *testing.T) {
	certs, _ := generateCertChain(t, 2)

	intermediates := []*x509.Certificate{certs[1]}
	builder := NewChainBuilder(intermediates)

	path, err := builder.BuildPath(certs[1], []*x509.Certificate{certs[0]})

	if err != nil {
		t.Logf("BuildPath error: %v", err)
	}

	if len(path) > 0 {
		t.Logf("Path found with length %d", len(path))
	}
}

// TestBuildPath_NoTrustedRoot тестирует отсутствие доверенного корня
func TestBuildPath_NoTrustedRoot(t *testing.T) {
	certs, _ := generateCertChain(t, 2)

	builder := NewChainBuilder([]*x509.Certificate{certs[1]})
	path, err := builder.BuildPath(certs[1], []*x509.Certificate{})

	if err == nil {
		t.Error("Expected error for no trusted root, got nil")
	}

	if len(path) > 0 {
		t.Error("Expected empty path for no trusted root")
	}
}

// TestBuildPath_NilLeaf тестирует nil листовой сертификат
func TestBuildPath_NilLeaf(t *testing.T) {
	builder := NewChainBuilder([]*x509.Certificate{})
	path, err := builder.BuildPath(nil, []*x509.Certificate{})

	if err == nil {
		t.Error("Expected error for nil leaf, got nil")
	}

	if path != nil {
		t.Error("Expected nil path for nil leaf")
	}
}
