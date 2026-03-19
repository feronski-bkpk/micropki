package revocation

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// CRLCacheEntry представляет запись в кэше CRL
type CRLCacheEntry struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
	crlURL    string
}

// CRLChecker проверяет статус через CRL
type CRLChecker struct {
	client       *http.Client
	cache        map[string]*CRLCacheEntry
	cacheMu      sync.RWMutex
	cacheTTL     int
	allowExpired bool
	maxCRLSize   int64
	logger       Logger
}

// NewCRLChecker создает новый CRL проверяльщик
func NewCRLChecker(config RevocationCheckerConfig) *CRLChecker {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &CRLChecker{
		client:       config.HTTPClient,
		cache:        make(map[string]*CRLCacheEntry),
		cacheTTL:     config.CacheTTL,
		allowExpired: config.AllowExpiredCRL,
		maxCRLSize:   config.MaxCRLSize,
		logger:       config.Logger,
	}
}

// Check выполняет CRL проверку
func (cc *CRLChecker) Check(cert, issuer *x509.Certificate) *RevocationResult {
	crlURLs := getCRLURLs(cert)
	if len(crlURLs) == 0 {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  "CRL URL не найден в расширении CDP",
		}
	}

	for _, crlURL := range crlURLs {
		result := cc.checkWithCRL(cert, issuer, crlURL)
		if result.Status != StatusUnknown {
			return result
		}
	}

	return &RevocationResult{
		Status: StatusUnknown,
		Error:  "не удалось получить действительный CRL",
	}
}

func (cc *CRLChecker) checkWithCRL(cert, issuer *x509.Certificate, crlURL string) *RevocationResult {
	cacheKey := crlURL
	cc.cacheMu.RLock()
	entry, ok := cc.cache[cacheKey]
	cc.cacheMu.RUnlock()

	var crl *x509.RevocationList
	var err error

	if ok && time.Since(entry.fetchedAt) < time.Duration(cc.cacheTTL)*time.Second {
		crl = entry.crl
	} else {
		crl, err = cc.fetchCRL(crlURL, issuer)
		if err != nil {
			if cc.logger != nil {
				cc.logger.Printf("WARN: Не удалось загрузить CRL %s: %v", crlURL, err)
			}
			return &RevocationResult{
				Status: StatusUnknown,
				Error:  err.Error(),
			}
		}

		if cc.cacheTTL > 0 {
			cc.cacheMu.Lock()
			cc.cache[cacheKey] = &CRLCacheEntry{
				crl:       crl,
				fetchedAt: time.Now(),
				crlURL:    crlURL,
			}
			cc.cacheMu.Unlock()
		}
	}

	now := time.Now()
	if now.After(crl.NextUpdate) && !cc.allowExpired {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("CRL истек %v", crl.NextUpdate),
		}
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("недействительная подпись CRL: %v", err),
		}
	}

	for _, revokedCert := range crl.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			reason := "unspecified"

			return &RevocationResult{
				Status:           StatusRevoked,
				RevocationTime:   &revokedCert.RevocationTime,
				RevocationReason: &reason,
			}
		}
	}

	return &RevocationResult{
		Status: StatusGood,
	}
}

func (cc *CRLChecker) fetchCRL(crlURL string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	var data []byte
	var err error

	if strings.HasPrefix(crlURL, "http://") || strings.HasPrefix(crlURL, "https://") {
		data, err = cc.fetchHTTPCRL(crlURL)
	} else {
		data, err = os.ReadFile(crlURL)
	}

	if err != nil {
		return nil, err
	}

	return parseCRL(data)
}

func (cc *CRLChecker) fetchHTTPCRL(url string) ([]byte, error) {
	resp, err := cc.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP статус %d", resp.StatusCode)
	}

	if cc.maxCRLSize > 0 && resp.ContentLength > cc.maxCRLSize {
		return nil, fmt.Errorf("CRL слишком большой: %d байт", resp.ContentLength)
	}

	return io.ReadAll(resp.Body)
}

// getCRLURLs извлекает URL точек распространения CRL из сертификата
func getCRLURLs(cert *x509.Certificate) []string {
	var urls []string

	for _, cdp := range cert.CRLDistributionPoints {
		if cdp != "" {
			urls = append(urls, cdp)
		}
	}

	return urls
}

// parseCRL парсит CRL из PEM или DER формата
func parseCRL(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		if block.Type == "X509 CRL" {
			return x509.ParseRevocationList(block.Bytes)
		}
		data = block.Bytes
	}

	return x509.ParseRevocationList(data)
}
