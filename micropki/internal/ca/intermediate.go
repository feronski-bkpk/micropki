// Package ca implements Certificate Authority operations
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/micropki/internal/certs"
	cryptolib "micropki/micropki/internal/crypto" // алиас для внутреннего пакета
	"micropki/micropki/internal/csr"
	"micropki/micropki/internal/templates"
)

// CAConfig holds configuration for CA operations
type CAConfig struct {
	RootCertPath   string
	RootKeyPath    string
	RootPassphrase []byte
	Subject        *pkix.Name
	KeyType        string
	KeySize        int
	Passphrase     []byte
	OutDir         string
	ValidityDays   int
	PathLen        int
}

// IssueIntermediate issues an Intermediate CA certificate signed by Root CA
// Implements CLI-7 and PKI-6, PKI-7 requirements
func IssueIntermediate(cfg *CAConfig) error {
	// 1. Load Root CA certificate and key
	rootCert, err := certs.LoadCertificate(cfg.RootCertPath)
	if err != nil {
		return fmt.Errorf("failed to load root certificate: %w", err)
	}

	rootKey, err := cryptolib.LoadEncryptedPrivateKey(cfg.RootKeyPath, cfg.RootPassphrase)
	if err != nil {
		return fmt.Errorf("failed to load root private key: %w", err)
	}

	// 2. Generate Intermediate CA key pair
	keyPair, err := cryptolib.GenerateKeyPair(cfg.KeyType, cfg.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate intermediate key pair: %w", err)
	}

	// 3. Generate serial number
	serialNumber, err := templates.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// 4. Set validity period
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, cfg.ValidityDays)

	// 5. Create Intermediate CA template
	tmplCfg := &templates.TemplateConfig{
		Subject:      cfg.Subject,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    keyPair.PublicKey,
		IsCA:         true,
		MaxPathLen:   cfg.PathLen,
	}

	template := templates.NewIntermediateCATemplate(tmplCfg)

	// 6. Create certificate (Root signs Intermediate)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,          // template for new cert
		rootCert,          // issuer cert (Root)
		keyPair.PublicKey, // public key of new cert
		rootKey,           // private key of issuer
	)
	if err != nil {
		return fmt.Errorf("failed to create intermediate certificate: %w", err)
	}

	// 7. Parse the certificate to verify
	intermediateCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// 8. Verify the certificate
	if err := intermediateCert.CheckSignatureFrom(rootCert); err != nil {
		return fmt.Errorf("generated certificate signature verification failed: %w", err)
	}

	// 9. Save encrypted private key
	privateKeyPath := filepath.Join(cfg.OutDir, "private", "intermediate.key.pem")
	if err := cryptolib.SaveEncryptedPrivateKey(keyPair.PrivateKey, privateKeyPath, cfg.Passphrase); err != nil {
		return fmt.Errorf("failed to save intermediate private key: %w", err)
	}
	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return fmt.Errorf("failed to set private key permissions: %w", err)
	}

	// 10. Save certificate
	certPath := filepath.Join(cfg.OutDir, "certs", "intermediate.cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return fmt.Errorf("failed to save intermediate certificate: %w", err)
	}

	// 11. Update policy document
	if err := updatePolicyWithIntermediate(cfg.OutDir, intermediateCert, cfg); err != nil {
		return fmt.Errorf("failed to update policy document: %w", err)
	}

	fmt.Printf("\nIntermediate CA successfully created!\n")
	fmt.Printf("Certificate: %s\n", certPath)
	fmt.Printf("Private key: %s (encrypted)\n", privateKeyPath)
	fmt.Printf("Serial number: %X\n", intermediateCert.SerialNumber)

	return nil
}

// IssueCertificateConfig holds configuration for issuing end-entity certificates
type IssueCertificateConfig struct {
	CACertPath   string
	CAKeyPath    string
	CAPassphrase []byte
	Template     templates.TemplateType
	Subject      *pkix.Name
	SANs         []templates.SAN
	CSRPath      string // optional, for signing external CSR
	OutDir       string
	ValidityDays int
	KeyType      string // for internal key generation
	KeySize      int    // for internal key generation
}

// IssueCertificate issues an end-entity certificate signed by Intermediate CA
// Implements CLI-8 and PKI-8, PKI-9, PKI-11 requirements
func IssueCertificate(cfg *IssueCertificateConfig) error {
	// 1. Load CA certificate and key
	caCert, err := certs.LoadCertificate(cfg.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caKey, err := cryptolib.LoadEncryptedPrivateKey(cfg.CAKeyPath, cfg.CAPassphrase)
	if err != nil {
		return fmt.Errorf("failed to load CA private key: %w", err)
	}

	// 2. Verify CA is not root? (optional, but good practice)
	if caCert.IsCA && caCert.MaxPathLen == 0 {
		// This is fine - intermediate with pathlen 0 can still issue leaf certs
	}

	// 3. Validate template compatibility with SANs
	if err := templates.ValidateTemplateCompatibility(cfg.Template, cfg.SANs); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	var publicKey crypto.PublicKey
	var privateKey crypto.PrivateKey
	var certSubject *pkix.Name
	var certSANs []templates.SAN

	// 4. Handle CSR or generate new key pair
	if cfg.CSRPath != "" {
		// Sign external CSR
		certSubject, certSANs, publicKey, err = processExternalCSR(cfg)
		if err != nil {
			return fmt.Errorf("failed to process external CSR: %w", err)
		}
		// No private key to save for external CSR
	} else {
		// Generate new key pair
		keyPair, err := cryptolib.GenerateKeyPair(cfg.KeyType, cfg.KeySize)
		if err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}
		publicKey = keyPair.PublicKey
		privateKey = keyPair.PrivateKey
		certSubject = cfg.Subject
		certSANs = cfg.SANs
	}

	// 5. Generate serial number
	serialNumber, err := templates.NewSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// 6. Set validity period
	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, cfg.ValidityDays)

	// 7. Create template based on type
	tmplCfg := &templates.TemplateConfig{
		Subject:      certSubject,
		SANs:         certSANs,
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		PublicKey:    publicKey,
	}

	var template *x509.Certificate
	switch cfg.Template {
	case templates.Server:
		template, err = templates.NewServerTemplate(tmplCfg)
	case templates.Client:
		template, err = templates.NewClientTemplate(tmplCfg)
	case templates.CodeSigning:
		template, err = templates.NewCodeSigningTemplate(tmplCfg)
	default:
		return fmt.Errorf("unsupported template type: %s", cfg.Template)
	}
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	// 8. Create certificate (CA signs the new certificate)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,  // template for new cert
		caCert,    // issuer cert (Intermediate CA)
		publicKey, // public key of new cert
		caKey,     // private key of issuer
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// 9. Parse the certificate to get info for filename
	newCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// 10. Determine filename based on CN or first DNS name
	filename := generateCertFilename(newCert, cfg.Template)

	// 11. Save certificate
	certPath := filepath.Join(cfg.OutDir, filename+".cert.pem")
	if err := certs.SaveCertificate(certDER, certPath); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// 12. Save private key if we generated one
	var keyPath string
	if privateKey != nil {
		keyPath = filepath.Join(cfg.OutDir, filename+".key.pem")
		if err := cryptolib.SavePrivateKeyUnencrypted(privateKey, keyPath); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			return fmt.Errorf("failed to set private key permissions: %w", err)
		}
		fmt.Printf("WARNING: Private key stored unencrypted at %s\n", keyPath)
	}

	// 13. Log issuance (for audit)
	fmt.Printf("\nCertificate successfully issued!\n")
	fmt.Printf("Type: %s\n", cfg.Template)
	fmt.Printf("Certificate: %s\n", certPath)
	if keyPath != "" {
		fmt.Printf("Private key: %s (UNENCRYPTED)\n", keyPath)
	}
	fmt.Printf("Serial number: %X\n", newCert.SerialNumber)
	if len(cfg.SANs) > 0 {
		fmt.Printf("Subject Alternative Names:\n")
		for _, san := range cfg.SANs {
			fmt.Printf("  %s: %s\n", san.Type, san.Value)
		}
	}

	return nil
}

// processExternalCSR handles signing of an external CSR
func processExternalCSR(cfg *IssueCertificateConfig) (*pkix.Name, []templates.SAN, crypto.PublicKey, error) {
	// Read CSR file
	csrPEM, err := os.ReadFile(cfg.CSRPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CSR file: %w", err)
	}

	// Parse and verify CSR
	parsedCSR, err := csr.ParseAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Check if CSR requests CA (should be rejected for end-entity)
	if csr.IsCARequest(parsedCSR) {
		return nil, nil, nil, fmt.Errorf("CSR requests CA=true - not allowed for end-entity certificates")
	}

	// Get subject from CSR
	subject := csr.GetSubjectFromCSR(parsedCSR)

	// Get SANs from CSR
	sans, err := csr.GetSANsFromCSR(parsedCSR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract SANs from CSR: %w", err)
	}

	// Validate CSR compatibility with template
	if err := csr.ValidateCSRForTemplate(parsedCSR, cfg.Template); err != nil {
		return nil, nil, nil, fmt.Errorf("CSR incompatible with template: %w", err)
	}

	// Extract public key
	publicKey, err := csr.ExtractPublicKey(parsedCSR)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return subject, sans, publicKey, nil
}

// generateCertFilename creates a filename based on certificate content
func generateCertFilename(cert *x509.Certificate, tmplType templates.TemplateType) string {
	// Try to use first DNS name for server certs
	if tmplType == templates.Server && len(cert.DNSNames) > 0 {
		return sanitizeFilename(cert.DNSNames[0])
	}
	// Try to use email for client certs
	if tmplType == templates.Client && len(cert.EmailAddresses) > 0 {
		return sanitizeFilename(cert.EmailAddresses[0])
	}
	// Fall back to Common Name
	if cert.Subject.CommonName != "" {
		return sanitizeFilename(cert.Subject.CommonName)
	}
	// Last resort: use serial number
	return fmt.Sprintf("cert-%X", cert.SerialNumber)
}

// sanitizeFilename removes characters not safe for filenames
func sanitizeFilename(name string) string {
	// Replace problematic characters with underscore
	result := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// updatePolicyWithIntermediate appends Intermediate CA info to policy.txt
func updatePolicyWithIntermediate(outDir string, cert *x509.Certificate, cfg *CAConfig) error {
	policyPath := filepath.Join(outDir, "policy.txt")

	// Read existing policy or create new
	var content []byte
	if _, err := os.Stat(policyPath); err == nil {
		content, err = os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("failed to read existing policy: %w", err)
		}
	}

	// Append Intermediate CA section
	policy := string(content)
	policy += "\n\n"
	policy += "INTERMEDIATE CA CERTIFICATE\n"
	policy += strings.Repeat("=", 30) + "\n\n"
	policy += fmt.Sprintf("Creation Date: %s\n", time.Now().UTC().Format(time.RFC3339))
	policy += fmt.Sprintf("Subject: %s\n", cert.Subject)
	policy += fmt.Sprintf("Issuer (Root CA): %s\n", cert.Issuer)
	policy += fmt.Sprintf("Serial Number (hex): %X\n", cert.SerialNumber)
	policy += "Validity Period:\n"
	policy += fmt.Sprintf("  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	policy += fmt.Sprintf("  Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))

	// Get key algorithm info
	algo, size, _ := certs.GetKeyAlgorithm(cert.PublicKey)
	policy += fmt.Sprintf("Key Algorithm: %s-%d\n", algo, size)

	policy += fmt.Sprintf("Path Length Constraint: %d\n", cfg.PathLen)
	policy += fmt.Sprintf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)

	return os.WriteFile(policyPath, []byte(policy), 0644)
}
