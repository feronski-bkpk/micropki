// Package transparency реализует симуляцию Certificate Transparency журнала
package transparency

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CTLog представляет журнал Certificate Transparency
type CTLog struct {
	path string
	mu   sync.Mutex
}

// NewCTLog создает новый экземпляр CT-журнала
func NewCTLog(logPath string) (*CTLog, error) {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("не удалось создать директорию для CT-журнала: %w", err)
	}

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
			return nil, fmt.Errorf("не удалось создать CT-журнал: %w", err)
		}
	}

	return &CTLog{path: logPath}, nil
}

// LogCertificate добавляет запись о выпущенном сертификате
func (c *CTLog) LogCertificate(cert *x509.Certificate, issuerDN string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	fingerprint := sha256.Sum256(cert.Raw)

	entry := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339),
		hex.EncodeToString(cert.SerialNumber.Bytes()),
		cert.Subject.String(),
		hex.EncodeToString(fingerprint[:]),
		issuerDN,
	)

	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("не удалось открыть CT-журнал: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("не удалось записать в CT-журнал: %w", err)
	}

	return nil
}

// VerifyInclusion проверяет наличие сертификата в журнале
func (c *CTLog) VerifyInclusion(serialHex string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		return false, fmt.Errorf("не удалось прочитать CT-журнал: %w", err)
	}

	return strings.Contains(string(data), serialHex), nil
}

// GetEntries возвращает все записи журнала
func (c *CTLog) GetEntries() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать CT-журнал: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var entries []string
	for _, line := range lines {
		if line != "" {
			entries = append(entries, line)
		}
	}

	return entries, nil
}
