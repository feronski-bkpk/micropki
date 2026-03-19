package revocation

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// RevocationStatus представляет статус отзыва
type RevocationStatus int

const (
	StatusGood RevocationStatus = iota
	StatusRevoked
	StatusUnknown
)

func (s RevocationStatus) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	case StatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// RevocationResult содержит результат проверки отзыва
type RevocationResult struct {
	Status           RevocationStatus `json:"status"`
	Method           string           `json:"method"`
	RevocationTime   *time.Time       `json:"revocation_time,omitempty"`
	RevocationReason *string          `json:"revocation_reason,omitempty"`
	Error            string           `json:"error,omitempty"`
}

// RevocationChecker реализует проверку отзыва с fallback логикой
type RevocationChecker struct {
	crlChecker  *CRLChecker
	ocspChecker *OCSPChecker
	logger      Logger
}

// Logger интерфейс для логирования
type Logger interface {
	Printf(format string, v ...interface{})
}

// RevocationCheckerConfig конфигурация для проверки отзыва
type RevocationCheckerConfig struct {
	HTTPClient      *http.Client
	CacheTTL        int
	MaxCRLSize      int64
	AllowExpiredCRL bool
	OCSPTimeout     time.Duration
	CRLTimeout      time.Duration
	Logger          Logger
}

// NewRevocationChecker создает новый проверяльщик отзыва
func NewRevocationChecker(config RevocationCheckerConfig) *RevocationChecker {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &RevocationChecker{
		crlChecker:  NewCRLChecker(config),
		ocspChecker: NewOCSPChecker(config),
		logger:      config.Logger,
	}
}

// CheckRevocation проверяет статус отзыва с приоритетом OCSP -> CRL
func (rc *RevocationChecker) CheckRevocation(
	cert *x509.Certificate,
	issuer *x509.Certificate,
) *RevocationResult {

	ocspURL := getOCSPURL(cert)
	crlURLs := getCRLURLs(cert)

	if rc.logger != nil {
		rc.logger.Printf("INFO: Проверка отзыва для %X", cert.SerialNumber)
		rc.logger.Printf("INFO:   OCSP URL: %s", ocspURL)
		rc.logger.Printf("INFO:   CRL URLs: %v", crlURLs)
	}

	// 1. Сначала пробуем OCSP если есть URL
	if ocspURL != "" {
		if rc.logger != nil {
			rc.logger.Printf("INFO: Попытка проверки OCSP для %X", cert.SerialNumber)
		}

		ocspResult := rc.ocspChecker.Check(cert, issuer)
		if ocspResult.Status != StatusUnknown {
			ocspResult.Method = "ocsp"
			if rc.logger != nil {
				rc.logger.Printf("INFO: OCSP успешен для %X: %s", cert.SerialNumber, ocspResult.Status)
			}
			return ocspResult
		}

		if rc.logger != nil {
			rc.logger.Printf("INFO: OCSP не удался (%s), переход на CRL", ocspResult.Error)
		}
	} else {
		if rc.logger != nil {
			rc.logger.Printf("INFO: OCSP URL не найден, переход на CRL")
		}
	}

	// 2. Fallback на CRL
	if len(crlURLs) > 0 {
		if rc.logger != nil {
			rc.logger.Printf("INFO: Попытка проверки CRL для %X", cert.SerialNumber)
		}

		crlResult := rc.crlChecker.Check(cert, issuer)
		if crlResult.Status != StatusUnknown {
			crlResult.Method = "crl"
			if rc.logger != nil {
				rc.logger.Printf("INFO: CRL успешен для %X: %s", cert.SerialNumber, crlResult.Status)
			}
			return crlResult
		}

		if rc.logger != nil {
			rc.logger.Printf("INFO: CRL не удался (%s)", crlResult.Error)
		}
	} else {
		if rc.logger != nil {
			rc.logger.Printf("INFO: CRL URL не найден")
		}
	}

	// 3. Оба метода не сработали
	if rc.logger != nil {
		rc.logger.Printf("WARN: Оба метода проверки отзыва не удались для %X", cert.SerialNumber)
	}

	return &RevocationResult{
		Status: StatusUnknown,
		Method: "both_failed",
		Error: fmt.Sprintf("OCSP: %v, CRL: %v",
			"не удалось выполнить проверку",
			"не удалось выполнить проверку"),
	}
}
