// Package main implements the MicroPKI command-line interface.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/micropki/internal/certs"
	"micropki/micropki/internal/crypto"
)

const (
	exitCodeSuccess = 0
	exitCodeError   = 1
)

type Config struct {
	Subject        string
	KeyType        string
	KeySize        int
	PassphraseFile string
	OutDir         string
	ValidityDays   int
	LogFile        string
	Force          bool
}

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	if err := run(os.Args[1:], logger); err != nil {
		logger.Printf("ERROR: %v", err)
		os.Exit(exitCodeError)
	}
}

func run(args []string, logger *log.Logger) error {
	if len(args) < 1 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "ca":
		if len(args) < 2 {
			return fmt.Errorf("missing subcommand for 'ca'\nUsage: micropki-cli ca <subcommand> [options]")
		}
		switch args[1] {
		case "init":
			return runCAInit(args[2:], logger)
		case "verify":
			return runCAVerify(args[2:], logger)
		default:
			return fmt.Errorf("unknown subcommand '%s' for 'ca'", args[1])
		}
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command '%s'", args[0])
	}
}

func printUsage() {
	fmt.Println("MicroPKI - Minimal Public Key Infrastructure Tool")
	fmt.Println("\nUsage: micropki-cli <command> [subcommand] [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  ca init    Initialize a new Root CA")
	fmt.Println("  ca verify  Verify a certificate")
	fmt.Println("\nCA Init Options:")
	fmt.Println("  --subject           Distinguished Name (required)")
	fmt.Println("                      Format: /CN=.../O=... or CN=...,O=...")
	fmt.Println("  --key-type          Key type: rsa or ecc (default: rsa)")
	fmt.Println("  --key-size          Key size: 4096 for RSA, 384 for ECC (required)")
	fmt.Println("  --passphrase-file   Path to file with passphrase (required)")
	fmt.Println("  --out-dir           Output directory (default: ./pki)")
	fmt.Println("  --validity-days     Validity period in days (default: 3650)")
	fmt.Println("  --log-file          Optional log file path")
	fmt.Println("  --force             Force overwrite existing files")
	fmt.Println("\nCA Verify Options:")
	fmt.Println("  --cert              Path to certificate file to verify")
}

func runCAInit(args []string, logger *log.Logger) error {
	initCmd := flag.NewFlagSet("init", flag.ContinueOnError)

	var config Config
	initCmd.StringVar(&config.Subject, "subject", "", "Distinguished Name (required)")
	initCmd.StringVar(&config.KeyType, "key-type", "rsa", "Key type: rsa or ecc (default: rsa)")
	initCmd.IntVar(&config.KeySize, "key-size", 0, "Key size: 4096 for RSA, 384 for ECC (required)")
	initCmd.StringVar(&config.PassphraseFile, "passphrase-file", "", "Path to file containing passphrase (required)")
	initCmd.StringVar(&config.OutDir, "out-dir", "./pki", "Output directory (default: ./pki)")
	initCmd.IntVar(&config.ValidityDays, "validity-days", 3650, "Validity period in days (default: 3650)")
	initCmd.StringVar(&config.LogFile, "log-file", "", "Optional log file path")
	initCmd.BoolVar(&config.Force, "force", false, "Force overwrite without confirmation")

	initCmd.SetOutput(os.Stderr)

	if err := initCmd.Parse(args); err != nil {
		return fmt.Errorf("failed to parse arguments: %w", err)
	}

	// Validation
	if config.Subject == "" {
		return fmt.Errorf("--subject is required and cannot be empty")
	}

	config.KeyType = strings.ToLower(config.KeyType)
	if config.KeyType != "rsa" && config.KeyType != "ecc" {
		return fmt.Errorf("--key-type must be either 'rsa' or 'ecc', got '%s'", config.KeyType)
	}

	if config.KeySize == 0 {
		return fmt.Errorf("--key-size is required")
	}
	switch config.KeyType {
	case "rsa":
		if config.KeySize != 4096 {
			return fmt.Errorf("for RSA, --key-size must be 4096, got %d", config.KeySize)
		}
	case "ecc":
		if config.KeySize != 384 {
			return fmt.Errorf("for ECC, --key-size must be 384, got %d", config.KeySize)
		}
	}

	if config.PassphraseFile == "" {
		return fmt.Errorf("--passphrase-file is required")
	}

	passphrase, err := readPassphraseFromFile(config.PassphraseFile)
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.SecureZero(passphrase)

	if config.ValidityDays <= 0 {
		return fmt.Errorf("--validity-days must be a positive integer, got %d", config.ValidityDays)
	}

	if err := setupLogging(logger, config.LogFile); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	logger.Printf("INFO: Starting Root CA initialization")
	logger.Printf("INFO: Subject: %s", config.Subject)
	logger.Printf("INFO: Key type: %s-%d", config.KeyType, config.KeySize)
	logger.Printf("INFO: Validity period: %d days", config.ValidityDays)

	if err := createOutputDirectories(config.OutDir, config.Force, logger); err != nil {
		return fmt.Errorf("failed to create output directories: %w", err)
	}

	// Generate key pair
	logger.Printf("INFO: Generating %s key pair...", config.KeyType)
	keyPair, err := crypto.GenerateKeyPair(config.KeyType, config.KeySize)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	logger.Printf("INFO: Key pair generated successfully")

	// Create certificate
	logger.Printf("INFO: Creating self-signed X.509 certificate...")

	subject, err := certs.ParseDN(config.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse subject DN: %w", err)
	}

	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, config.ValidityDays)

	template := certs.NewRootCATemplate(
		subject, subject, serialNumber,
		notBefore, notAfter,
		keyPair.PublicKey,
	)

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		keyPair.PublicKey, keyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}
	logger.Printf("INFO: Certificate created successfully")

	// Save files
	privateKeyPath := filepath.Join(config.OutDir, "private", "ca.key.pem")
	logger.Printf("INFO: Saving encrypted private key to %s", privateKeyPath)

	if err := crypto.SaveEncryptedPrivateKey(keyPair.PrivateKey, privateKeyPath, passphrase); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		logger.Printf("WARNING: Failed to set permissions on private key file: %v", err)
	}

	certPath := filepath.Join(config.OutDir, "certs", "ca.cert.pem")
	logger.Printf("INFO: Saving certificate to %s", certPath)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	policyPath := filepath.Join(config.OutDir, "policy.txt")
	logger.Printf("INFO: Generating policy document at %s", policyPath)

	if err := createPolicyDocument(policyPath, config, certDER, serialNumber, notBefore, notAfter); err != nil {
		return fmt.Errorf("failed to create policy document: %w", err)
	}

	logger.Printf("INFO: Root CA initialization completed successfully")
	logger.Printf("INFO: Certificate serial number: %X", serialNumber)

	fmt.Printf("\nRoot CA successfully initialized!\n")
	fmt.Printf("Certificate: %s\n", certPath)
	fmt.Printf("Private key: %s (encrypted)\n", privateKeyPath)
	fmt.Printf("Policy document: %s\n", policyPath)

	return nil
}

func runCAVerify(args []string, logger *log.Logger) error {
	verifyCmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	var certPath string
	verifyCmd.StringVar(&certPath, "cert", "", "Path to certificate file to verify")

	if err := verifyCmd.Parse(args); err != nil {
		return err
	}

	if certPath == "" {
		return fmt.Errorf("--cert is required")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate verification FAILED: %w", err)
	}

	fmt.Printf("Certificate verification PASSED\n")
	fmt.Printf("\nCertificate details:\n")
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Serial: %X\n", cert.SerialNumber)
	fmt.Printf("  Valid from: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Valid until: %s\n", cert.NotAfter.Format(time.RFC3339))

	return nil
}

func readPassphraseFromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open passphrase file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read passphrase file: %w", err)
	}

	passphrase := bytes.TrimRight(content, "\r\n")

	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase file is empty")
	}

	return passphrase, nil
}

func setupLogging(logger *log.Logger, logFile string) error {
	if logFile == "" {
		return nil
	}

	logDir := filepath.Dir(logFile)
	if logDir != "." && logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("cannot create log directory: %w", err)
		}
	}

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}

	logger.SetOutput(io.MultiWriter(os.Stderr, file))
	return nil
}

func createOutputDirectories(outDir string, force bool, logger *log.Logger) error {
	privateKeyPath := filepath.Join(outDir, "private", "ca.key.pem")
	certPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	existingFiles := []string{}
	for _, path := range []string{privateKeyPath, certPath, policyPath} {
		if _, err := os.Stat(path); err == nil {
			existingFiles = append(existingFiles, path)
		}
	}

	if len(existingFiles) > 0 && !force {
		fmt.Println("Warning: The following files already exist:")
		for _, f := range existingFiles {
			fmt.Printf("  %s\n", f)
		}
		fmt.Println("Use --force to overwrite them.")
		return fmt.Errorf("files would be overwritten, aborting")
	}

	dirs := []string{
		outDir,
		filepath.Join(outDir, "private"),
		filepath.Join(outDir, "certs"),
	}

	for _, dir := range dirs {
		mode := os.FileMode(0755)
		if strings.HasSuffix(dir, "private") {
			mode = 0700
		}

		if err := os.MkdirAll(dir, mode); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		if err := os.Chmod(dir, mode); err != nil {
			logger.Printf("WARNING: Failed to set permissions on %s: %v", dir, err)
		}
	}

	return nil
}

func createPolicyDocument(path string, config Config, certDER []byte,
	serialNumber *big.Int, notBefore, notAfter time.Time) error {

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for policy: %w", err)
	}

	var policy strings.Builder
	policy.WriteString("MICROPKI CERTIFICATE POLICY DOCUMENT\n")
	policy.WriteString(strings.Repeat("=", 40) + "\n\n")

	fmt.Fprintf(&policy, "Policy Version: 1.0\n")
	policy.WriteString(fmt.Sprintf("Creation Date: %s\n", time.Now().UTC().Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("CA Name (Subject): %s\n", cert.Subject))
	policy.WriteString(fmt.Sprintf("Certificate Serial Number (hex): %X\n", serialNumber))
	fmt.Fprintf(&policy, "Validity Period:\n")
	policy.WriteString(fmt.Sprintf("  Not Before: %s\n", notBefore.Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("  Not After:  %s\n", notAfter.Format(time.RFC3339)))
	policy.WriteString(fmt.Sprintf("Key Algorithm: %s-%d\n", config.KeyType, config.KeySize))
	policy.WriteString(fmt.Sprintf("Signature Algorithm: %s\n", cert.SignatureAlgorithm))

	policy.WriteString("\nCA Purpose:\n")
	policy.WriteString("  Root CA for MicroPKI demonstration and educational purposes.\n")
	policy.WriteString("  This CA is intended for testing and learning about PKI.\n")
	policy.WriteString("  NOT FOR PRODUCTION USE.\n")

	policy.WriteString("\nCertificate Extensions:\n")
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			policy.WriteString("  - Basic Constraints: CA=TRUE (critical)\n")
		}
		if ext.Id.Equal([]int{2, 5, 29, 15}) {
			policy.WriteString("  - Key Usage: keyCertSign, cRLSign (critical)\n")
		}
	}

	policy.WriteString("\nSecurity Measures:\n")
	policy.WriteString("  - Private key encrypted with AES-256-GCM\n")
	policy.WriteString("  - Private key file permissions: 0600\n")
	policy.WriteString("  - Private key directory permissions: 0700\n")
	policy.WriteString("  - All operations are logged\n")

	policy.WriteString("\n" + strings.Repeat("-", 40) + "\n")
	policy.WriteString("END OF POLICY DOCUMENT\n")

	return os.WriteFile(path, []byte(policy.String()), 0644)
}
