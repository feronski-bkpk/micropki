// Package templates implements X.509 certificate templates for different use cases.
// Supports server, client, and code signing certificates with proper extensions
// according to RFC 5280.
package templates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// TemplateType defines the type of certificate template
type TemplateType string

const (
	// Server template for TLS server certificates
	Server TemplateType = "server"
	// Client template for TLS client certificates
	Client TemplateType = "client"
	// CodeSigning template for code signing certificates
	CodeSigning TemplateType = "code_signing"
)

// SAN represents a Subject Alternative Name entry
type SAN struct {
	Type  string // dns, ip, email, uri
	Value string
}

// TemplateConfig holds configuration for certificate templates
type TemplateConfig struct {
	Subject      *pkix.Name
	SANs         []SAN
	SerialNumber *SerialNumber // Мы создадим этот тип позже
	NotBefore    time.Time
	NotAfter     time.Time
	PublicKey    interface{}
	IsCA         bool
	MaxPathLen   int
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
}

// NewServerTemplate creates a template for server authentication certificates
// Implements PKI-8 requirements for server certificates:
// - Basic Constraints: CA=FALSE (critical)
// - Key Usage: digitalSignature, keyEncipherment (for RSA) or digitalSignature (for ECC)
// - Extended Key Usage: serverAuth
// - Subject Alternative Name: at least one DNS name or IP address
func NewServerTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	if len(cfg.SANs) == 0 {
		return nil, fmt.Errorf("server certificate requires at least one SAN (DNS or IP)")
	}

	// Validate that we have at least one DNS or IP SAN
	hasValidSAN := false
	for _, san := range cfg.SANs {
		if san.Type == "dns" || san.Type == "ip" {
			hasValidSAN = true
			break
		}
	}
	if !hasValidSAN {
		return nil, fmt.Errorf("server certificate must have at least one DNS name or IP address in SAN")
	}

	// Build DNS names, IP addresses, etc. from SANs
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (critical)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature, keyEncipherment (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		// Extended Key Usage: serverAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// Subject Alternative Name
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses,
		URIs:           uris,

		// Subject Key Identifier will be generated automatically
		// Authority Key Identifier will be set by the signer
	}

	return template, nil
}

// NewClientTemplate creates a template for client authentication certificates
// Implements PKI-8 requirements for client certificates:
// - Basic Constraints: CA=FALSE (critical)
// - Key Usage: digitalSignature
// - Extended Key Usage: clientAuth
// - Subject Alternative Name: should contain email if provided
func NewClientTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	// Build DNS names, IP addresses, etc. from SANs
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (critical)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature,

		// Extended Key Usage: clientAuth
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		// Subject Alternative Name
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emailAddresses,
		URIs:           uris,
	}

	return template, nil
}

// NewCodeSigningTemplate creates a template for code signing certificates
// Implements PKI-8 requirements for code signing certificates:
// - Basic Constraints: CA=FALSE (critical)
// - Key Usage: digitalSignature
// - Extended Key Usage: codeSigning
// - Subject Alternative Name: not required, limited to DNS/URI if provided
func NewCodeSigningTemplate(cfg *TemplateConfig) (*x509.Certificate, error) {
	// For code signing, we should validate that no IP or email SANs are present
	for _, san := range cfg.SANs {
		if san.Type == "ip" || san.Type == "email" {
			return nil, fmt.Errorf("code signing certificate cannot have IP or email SANs")
		}
	}

	// Build DNS names, IP addresses, etc. from SANs
	dnsNames, ipAddresses, emailAddresses, uris := splitSANs(cfg.SANs)

	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=FALSE (critical)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key Usage: digitalSignature (PKI-8)
		KeyUsage: x509.KeyUsageDigitalSignature,

		// Extended Key Usage: codeSigning
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},

		// Subject Alternative Name (limited to DNS/URI)
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,    // Should be empty due to validation above
		EmailAddresses: emailAddresses, // Should be empty due to validation above
		URIs:           uris,
	}

	return template, nil
}

// NewIntermediateCATemplate creates a template for Intermediate CA certificates
// Implements PKI-7 requirements:
// - Basic Constraints: CA=TRUE, pathLenConstraint (critical)
// - Key Usage: keyCertSign, cRLSign (critical)
func NewIntermediateCATemplate(cfg *TemplateConfig) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: cfg.SerialNumber.BigInt(),
		Subject:      *cfg.Subject,
		NotBefore:    cfg.NotBefore,
		NotAfter:     cfg.NotAfter,

		// Basic Constraints: CA=TRUE, pathLenConstraint (critical)
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            cfg.MaxPathLen,
		MaxPathLenZero:        cfg.MaxPathLen == 0,

		// Key Usage: keyCertSign, cRLSign (critical)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		// Subject Key Identifier will be generated automatically
		// Authority Key Identifier will be set by the signer
	}

	return template
}

// ValidateTemplateCompatibility checks if the template supports the provided SAN types
func ValidateTemplateCompatibility(tmplType TemplateType, sans []SAN) error {
	switch tmplType {
	case Server:
		hasDNSorIP := false
		for _, san := range sans {
			if san.Type == "dns" || san.Type == "ip" {
				hasDNSorIP = true
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("server template requires at least one DNS or IP SAN")
		}

	case Client:
		// Client can have any SAN types, no strict requirements

	case CodeSigning:
		for _, san := range sans {
			if san.Type == "ip" || san.Type == "email" {
				return fmt.Errorf("code signing template does not support IP or email SANs")
			}
		}
	}

	return nil
}

// ParseSANString parses a SAN string of format "type:value"
// Supported types: dns, ip, email, uri
func ParseSANString(san string) (SAN, error) {
	parts := strings.SplitN(san, ":", 2)
	if len(parts) != 2 {
		return SAN{}, fmt.Errorf("invalid SAN format: %s (expected type:value)", san)
	}

	sanType := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	if value == "" {
		return SAN{}, fmt.Errorf("empty SAN value for type %s", sanType)
	}

	// Validate based on type
	switch sanType {
	case "dns", "email", "uri":
		// Basic validation, actual format will be checked during encoding
	case "ip":
		if net.ParseIP(value) == nil {
			return SAN{}, fmt.Errorf("invalid IP address: %s", value)
		}
	default:
		return SAN{}, fmt.Errorf("unsupported SAN type: %s (supported: dns, ip, email, uri)", sanType)
	}

	return SAN{Type: sanType, Value: value}, nil
}

// splitSANs separates SANs by type
func splitSANs(sans []SAN) (dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL) {
	for _, san := range sans {
		switch san.Type {
		case "dns":
			dnsNames = append(dnsNames, san.Value)
		case "ip":
			if ip := net.ParseIP(san.Value); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			}
		case "email":
			emailAddresses = append(emailAddresses, san.Value)
		case "uri":
			if u, err := url.Parse(san.Value); err == nil {
				uris = append(uris, u)
			}
		}
	}
	return dnsNames, ipAddresses, emailAddresses, uris
}
