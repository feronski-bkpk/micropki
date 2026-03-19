package validation

import (
	"crypto/x509"
	"fmt"
	"time"
)

// ValidationResult содержит результат проверки цепочки
type ValidationResult struct {
	OverallStatus  bool                     `json:"overall_status"`
	Chain          []*CertificateValidation `json:"chain"`
	FirstError     string                   `json:"first_error,omitempty"`
	ValidationTime time.Time                `json:"validation_time"`
}

// CertificateValidation содержит результат проверки одного сертификата
type CertificateValidation struct {
	Subject        string    `json:"subject"`
	SerialNumber   string    `json:"serial_number"`
	SignatureValid bool      `json:"signature_valid"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	ValidityPeriod bool      `json:"validity_period"`
	IsCA           bool      `json:"is_ca"`
	CAValid        bool      `json:"ca_valid"`
	KeyUsageValid  bool      `json:"key_usage_valid"`
	PathLenValid   bool      `json:"path_len_valid"`
	Errors         []string  `json:"errors,omitempty"`
}

// ValidatorConfig содержит конфигурацию валидатора
type ValidatorConfig struct {
	ValidationTime *time.Time
	MaxChainLength int
	CheckKeyUsage  bool
}

// PathValidator реализует проверку путей сертификатов по RFC 5280
type PathValidator struct {
	trustedRoots []*x509.Certificate
	config       ValidatorConfig
}

// NewPathValidator создает новый валидатор
func NewPathValidator(trustedRoots []*x509.Certificate, config ValidatorConfig) *PathValidator {
	if config.MaxChainLength == 0 {
		config.MaxChainLength = 10
	}
	if config.ValidationTime == nil {
		now := time.Now()
		config.ValidationTime = &now
	}
	return &PathValidator{
		trustedRoots: trustedRoots,
		config:       config,
	}
}

// Validate выполняет полную проверку цепочки сертификатов
func (pv *PathValidator) Validate(chain []*x509.Certificate) *ValidationResult {
	result := &ValidationResult{
		ValidationTime: *pv.config.ValidationTime,
		Chain:          make([]*CertificateValidation, 0, len(chain)),
		OverallStatus:  true,
	}

	if len(chain) == 0 {
		result.OverallStatus = false
		result.FirstError = "пустая цепочка сертификатов"
		return result
	}

	for i, cert := range chain {
		var issuer *x509.Certificate
		if i < len(chain)-1 {
			issuer = chain[i+1]
		}

		certVal := pv.validateCertificate(cert, issuer, i == len(chain)-1, len(chain), i)
		result.Chain = append(result.Chain, certVal)

		if !certVal.SignatureValid || !certVal.ValidityPeriod {
			result.OverallStatus = false
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("ошибка в сертификате %d: %s", i, certVal.Errors[0])
			}
		}
	}

	return result
}
