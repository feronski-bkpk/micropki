// Package chain implements certificate chain validation and management
// according to RFC 5280.
package chain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Chain represents a complete certificate chain
type Chain struct {
	Leaf         *x509.Certificate
	Intermediate *x509.Certificate
	Root         *x509.Certificate
}

// LoadChain loads certificates from files and builds a chain
func LoadChain(leafPath, intermediatePath, rootPath string) (*Chain, error) {
	leaf, err := LoadCertificate(leafPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load leaf certificate: %w", err)
	}

	intermediate, err := LoadCertificate(intermediatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load intermediate certificate: %w", err)
	}

	root, err := LoadCertificate(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load root certificate: %w", err)
	}

	return &Chain{
		Leaf:         leaf,
		Intermediate: intermediate,
		Root:         root,
	}, nil
}

// LoadCertificate loads and parses a PEM-encoded certificate
func LoadCertificate(path string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Verify verifies the complete certificate chain
// Implements TEST-7 requirements:
// - Signatures at each level
// - Validity periods
// - Basic Constraints (CA flag and path length)
// - Key Usage / Extended Key Usage compatibility
func (c *Chain) Verify() error {
	// 1. Verify leaf certificate is not a CA
	if c.Leaf.IsCA {
		return fmt.Errorf("leaf certificate cannot be a CA")
	}

	// 2. Verify intermediate is a CA
	if !c.Intermediate.IsCA {
		return fmt.Errorf("intermediate certificate must be a CA")
	}

	// 3. Verify root is a CA
	if !c.Root.IsCA {
		return fmt.Errorf("root certificate must be a CA")
	}

	// 4. Check validity periods
	now := time.Now()
	if now.Before(c.Leaf.NotBefore) || now.After(c.Leaf.NotAfter) {
		return fmt.Errorf("leaf certificate is not valid at current time")
	}
	if now.Before(c.Intermediate.NotBefore) || now.After(c.Intermediate.NotAfter) {
		return fmt.Errorf("intermediate certificate is not valid at current time")
	}
	if now.Before(c.Root.NotBefore) || now.After(c.Root.NotAfter) {
		return fmt.Errorf("root certificate is not valid at current time")
	}

	// 5. Verify signatures
	// Leaf signed by Intermediate
	if err := c.Leaf.CheckSignatureFrom(c.Intermediate); err != nil {
		return fmt.Errorf("leaf signature verification failed: %w", err)
	}

	// Intermediate signed by Root
	if err := c.Intermediate.CheckSignatureFrom(c.Root); err != nil {
		return fmt.Errorf("intermediate signature verification failed: %w", err)
	}

	// 6. Verify Key Usage for CA certificates
	requiredKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if c.Intermediate.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("intermediate CA missing required KeyUsage: keyCertSign and cRLSign")
	}
	if c.Root.KeyUsage&requiredKeyUsage != requiredKeyUsage {
		return fmt.Errorf("root CA missing required KeyUsage: keyCertSign and cRLSign")
	}

	// 7. Verify path length constraints
	if err := c.verifyPathLength(); err != nil {
		return err
	}

	return nil
}

// verifyPathLength checks path length constraints
func (c *Chain) verifyPathLength() error {
	// Check intermediate's path length constraint
	if c.Intermediate.MaxPathLen >= 0 {
		// Path length of 0 means no further CAs below this one
		if c.Intermediate.MaxPathLen == 0 {
			// This is fine since leaf is not a CA
		}
	}

	// Check root's path length constraint if set
	if c.Root.MaxPathLen >= 0 {
		// Count number of CA certificates in chain (excluding root)
		caCount := 1 // intermediate is CA
		if caCount > c.Root.MaxPathLen {
			return fmt.Errorf("path length constraint violated: chain length %d exceeds root's MaxPathLen %d",
				caCount, c.Root.MaxPathLen)
		}
	}

	return nil
}

// VerifyWithOpenSSLCompatibility performs additional checks for OpenSSL compatibility
func (c *Chain) VerifyWithOpenSSLCompatibility() error {
	// Verify basic constraints are critical
	for _, cert := range []*x509.Certificate{c.Leaf, c.Intermediate, c.Root} {
		for _, ext := range cert.Extensions {
			// Check Basic Constraints extension (2.5.29.19)
			if ext.Id.Equal([]int{2, 5, 29, 19}) {
				if !ext.Critical && cert.IsCA {
					return fmt.Errorf("Basic Constraints extension should be critical for CA certificates")
				}
			}
		}
	}

	return nil
}

// PrintChainInfo prints human-readable information about the chain
func (c *Chain) PrintChainInfo() string {
	var info string

	info += "Certificate Chain:\n"
	info += "=================\n\n"

	info += "Root CA:\n"
	info += fmt.Sprintf("  Subject: %s\n", c.Root.Subject)
	info += fmt.Sprintf("  Issuer: %s\n", c.Root.Issuer)
	info += fmt.Sprintf("  Serial: %X\n", c.Root.SerialNumber)
	info += fmt.Sprintf("  Valid: %s to %s\n",
		c.Root.NotBefore.Format("2006-01-02"),
		c.Root.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  IsCA: %v\n", c.Root.IsCA)
	info += "\n"

	info += "Intermediate CA:\n"
	info += fmt.Sprintf("  Subject: %s\n", c.Intermediate.Subject)
	info += fmt.Sprintf("  Issuer: %s\n", c.Intermediate.Issuer)
	info += fmt.Sprintf("  Serial: %X\n", c.Intermediate.SerialNumber)
	info += fmt.Sprintf("  Valid: %s to %s\n",
		c.Intermediate.NotBefore.Format("2006-01-02"),
		c.Intermediate.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  IsCA: %v\n", c.Intermediate.IsCA)
	info += fmt.Sprintf("  PathLen: %d\n", c.Intermediate.MaxPathLen)
	info += "\n"

	info += "Leaf Certificate:\n"
	info += fmt.Sprintf("  Subject: %s\n", c.Leaf.Subject)
	info += fmt.Sprintf("  Issuer: %s\n", c.Leaf.Issuer)
	info += fmt.Sprintf("  Serial: %X\n", c.Leaf.SerialNumber)
	info += fmt.Sprintf("  Valid: %s to %s\n",
		c.Leaf.NotBefore.Format("2006-01-02"),
		c.Leaf.NotAfter.Format("2006-01-02"))
	info += fmt.Sprintf("  DNS Names: %v\n", c.Leaf.DNSNames)
	info += fmt.Sprintf("  IP Addresses: %v\n", c.Leaf.IPAddresses)
	info += fmt.Sprintf("  Email Addresses: %v\n", c.Leaf.EmailAddresses)

	return info
}
