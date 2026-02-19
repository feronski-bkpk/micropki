// Package csr implements Certificate Signing Request operations
// including generation, parsing, and verification according to PKCS#10.
package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"micropki/micropki/internal/templates"
)

// CSRConfig holds configuration for generating a Certificate Signing Request
type CSRConfig struct {
	Subject    *pkix.Name
	SANs       []templates.SAN
	Key        crypto.PrivateKey
	IsCA       bool
	MaxPathLen int
}

// GenerateIntermediateCSR generates a CSR for an Intermediate CA
// Implements PKI-6 requirements:
// - Subject DN as provided
// - Public key from generated key pair
// - Basic Constraints extension (CA=TRUE, pathLenConstraint)
func GenerateIntermediateCSR(cfg *CSRConfig) ([]byte, error) {
	if cfg.Subject == nil {
		return nil, fmt.Errorf("subject is required")
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Build template for CSR
	template := &x509.CertificateRequest{
		Subject: *cfg.Subject,
		// Include Basic Constraints extension in CSR (PKI-6)
		Extensions: []pkix.Extension{},
	}

	// Add Basic Constraints extension if this is for a CA
	if cfg.IsCA {
		// Basic Constraints OID: 2.5.29.19
		// ASN.1 encoding for CA=TRUE, pathLenConstraint
		var extValue []byte
		if cfg.MaxPathLen >= 0 {
			// With pathLenConstraint
			extValue = []byte{0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, byte(cfg.MaxPathLen)}
		} else {
			// Without pathLenConstraint
			extValue = []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
		}

		template.Extensions = append(template.Extensions, pkix.Extension{
			Id:       []int{2, 5, 29, 19},
			Critical: true,
			Value:    extValue,
		})
	}

	// Generate CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// ParseAndVerifyCSR parses a PEM-encoded CSR and verifies its signature
func ParseAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	// Decode PEM
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE REQUEST)", block.Type)
	}

	// Parse CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Verify signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	return csr, nil
}

// ExtractPublicKey extracts the public key from a CSR
func ExtractPublicKey(csr *x509.CertificateRequest) (crypto.PublicKey, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR is nil")
	}
	return csr.PublicKey, nil
}

// IsCARequest checks if the CSR requests CA capabilities
func IsCARequest(csr *x509.CertificateRequest) bool {
	for _, ext := range csr.Extensions {
		// Check for Basic Constraints extension (2.5.29.19)
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			// Basic parsing would be complex, but we can check if it's marked as CA
			// For now, we'll assume if the extension exists, it's requesting CA
			return true
		}
	}
	return false
}

// GetSubjectFromCSR returns the subject from a CSR
func GetSubjectFromCSR(csr *x509.CertificateRequest) *pkix.Name {
	return &csr.Subject
}

// GetSANsFromCSR extracts Subject Alternative Names from a CSR
func GetSANsFromCSR(csr *x509.CertificateRequest) ([]templates.SAN, error) {
	var sans []templates.SAN

	// Add DNS names
	for _, dns := range csr.DNSNames {
		sans = append(sans, templates.SAN{Type: "dns", Value: dns})
	}

	// Add IP addresses
	for _, ip := range csr.IPAddresses {
		sans = append(sans, templates.SAN{Type: "ip", Value: ip.String()})
	}

	// Add email addresses
	for _, email := range csr.EmailAddresses {
		sans = append(sans, templates.SAN{Type: "email", Value: email})
	}

	// Add URIs
	for _, uri := range csr.URIs {
		sans = append(sans, templates.SAN{Type: "uri", Value: uri.String()})
	}

	return sans, nil
}

// ValidateCSRForTemplate checks if a CSR is compatible with a given template
func ValidateCSRForTemplate(csr *x509.CertificateRequest, tmplType templates.TemplateType) error {
	// Extract SANs from CSR
	sans, err := GetSANsFromCSR(csr)
	if err != nil {
		return fmt.Errorf("failed to extract SANs: %w", err)
	}

	// Validate template compatibility
	if err := templates.ValidateTemplateCompatibility(tmplType, sans); err != nil {
		return fmt.Errorf("CSR incompatible with template %s: %w", tmplType, err)
	}

	// Additional validations
	switch tmplType {
	case templates.Server:
		// Server certificates must have at least one DNS or IP SAN
		hasDNSorIP := false
		for _, san := range sans {
			if san.Type == "dns" || san.Type == "ip" {
				hasDNSorIP = true
				break
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("server certificate requires at least one DNS or IP SAN")
		}

	case templates.CodeSigning:
		// Code signing certificates should not request CA
		if IsCARequest(csr) {
			return fmt.Errorf("code signing certificate cannot be a CA")
		}
	}

	return nil
}
