package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"micropki/micropki/internal/templates"
)

// PolicyConfig содержит настройки политик безопасности
type PolicyConfig struct {
	// RSA минимальные размеры ключей
	MinRSAKeySizeRootCA         int
	MinRSAKeySizeIntermediateCA int
	MinRSAKeySizeEndEntity      int

	// ECC минимальные размеры ключей
	MinECCKeySizeRootCA         int
	MinECCKeySizeIntermediateCA int
	MinECCKeySizeEndEntity      int

	// Максимальные сроки действия (в днях)
	MaxRootValidityDays         int
	MaxIntermediateValidityDays int
	MaxEndEntityValidityDays    int

	// Настройки SAN
	RejectWildcards               bool
	AllowedSANTypesForServer      []string
	AllowedSANTypesForClient      []string
	AllowedSANTypesForCodeSigning []string
}

// DefaultPolicyConfig возвращает конфигурацию политик по умолчанию
func DefaultPolicyConfig() *PolicyConfig {
	return &PolicyConfig{
		MinRSAKeySizeRootCA:           4096,
		MinRSAKeySizeIntermediateCA:   3072,
		MinRSAKeySizeEndEntity:        2048,
		MinECCKeySizeRootCA:           384,
		MinECCKeySizeIntermediateCA:   384,
		MinECCKeySizeEndEntity:        256,
		MaxRootValidityDays:           3650,
		MaxIntermediateValidityDays:   1825,
		MaxEndEntityValidityDays:      365,
		RejectWildcards:               true,
		AllowedSANTypesForServer:      []string{"dns", "ip"},
		AllowedSANTypesForClient:      []string{"dns", "email"},
		AllowedSANTypesForCodeSigning: []string{"dns", "uri"},
	}
}

// KeySizeValidator проверяет размер ключа
func (p *PolicyConfig) ValidateKeySize(publicKey crypto.PublicKey, isCA bool, templateType templates.TemplateType) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()

		if isCA {
			if bits < p.MinRSAKeySizeRootCA {
				return fmt.Errorf("RSA ключ CA должен быть минимум %d бит, текущий: %d",
					p.MinRSAKeySizeRootCA, bits)
			}
		} else {
			if bits < p.MinRSAKeySizeEndEntity {
				return fmt.Errorf("RSA ключ конечного субъекта должен быть минимум %d бит, текущий: %d",
					p.MinRSAKeySizeEndEntity, bits)
			}
		}

		if bits < 2048 {
			return fmt.Errorf("RSA ключи менее 2048 бит запрещены, текущий: %d", bits)
		}

	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize

		if isCA {
			if bits < p.MinECCKeySizeRootCA {
				return fmt.Errorf("ECC ключ CA должен быть минимум %d бит, текущий: %d",
					p.MinECCKeySizeRootCA, bits)
			}
			if bits == 256 {
				return fmt.Errorf("P-256 не разрешен для сертификатов CA, используйте P-384 или выше")
			}
		} else {
			if bits < p.MinECCKeySizeEndEntity {
				return fmt.Errorf("ECC ключ конечного субъекта должен быть минимум %d бит, текущий: %d",
					p.MinECCKeySizeEndEntity, bits)
			}
		}

	default:
		return fmt.Errorf("неподдерживаемый тип ключа")
	}

	return nil
}

// ValidityValidator проверяет срок действия
func (p *PolicyConfig) ValidateValidity(validityDays int, isCA bool, isRoot bool) error {
	if isCA {
		if isRoot {
			if validityDays > p.MaxRootValidityDays {
				return fmt.Errorf("срок действия корневого CA превышает максимальный (%d дней): %d",
					p.MaxRootValidityDays, validityDays)
			}
		} else {
			if validityDays > p.MaxIntermediateValidityDays {
				return fmt.Errorf("срок действия промежуточного CA превышает максимальный (%d дней): %d",
					p.MaxIntermediateValidityDays, validityDays)
			}
		}
	} else {
		if validityDays > p.MaxEndEntityValidityDays {
			return fmt.Errorf("срок действия конечного сертификата превышает максимальный (%d дней): %d",
				p.MaxEndEntityValidityDays, validityDays)
		}
	}

	return nil
}

// SANValidator проверяет SAN на соответствие шаблону
func (p *PolicyConfig) ValidateSANs(sans []templates.SAN, templateType templates.TemplateType) error {
	if p.RejectWildcards {
		for _, san := range sans {
			if san.Type == "dns" && strings.Contains(san.Value, "*") {
				return fmt.Errorf("wildcard SAN (%s) запрещен политикой безопасности", san.Value)
			}
		}
	}

	if templateType == templates.CodeSigning {
		for _, san := range sans {
			if san.Type == "email" {
				return fmt.Errorf("сертификат подписи кода (code_signing) не может содержать email SAN")
			}
			if san.Type == "ip" {
				return fmt.Errorf("сертификат подписи кода (code_signing) не может содержать IP SAN")
			}
		}
	}

	var allowedTypes []string
	switch templateType {
	case templates.Server:
		allowedTypes = p.AllowedSANTypesForServer
	case templates.Client:
		allowedTypes = p.AllowedSANTypesForClient
	case templates.CodeSigning:
		allowedTypes = p.AllowedSANTypesForCodeSigning
	default:
		return fmt.Errorf("неизвестный тип шаблона: %s", templateType)
	}

	for _, san := range sans {
		allowed := false
		for _, t := range allowedTypes {
			if san.Type == t {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("тип SAN '%s' не разрешен для шаблона '%s'", san.Type, templateType)
		}
	}

	if templateType == templates.Server && len(sans) == 0 {
		return fmt.Errorf("серверный сертификат должен содержать хотя бы одно DNS или IP имя в SAN")
	}

	return nil
}

// AlgorithmValidator проверяет алгоритм подписи
func (p *PolicyConfig) ValidateSignatureAlgorithm(sigAlgo x509.SignatureAlgorithm) error {
	algoName := sigAlgo.String()

	if strings.Contains(algoName, "SHA1") || strings.Contains(algoName, "SHA-1") {
		return fmt.Errorf("алгоритм SHA-1 запрещен, используйте SHA-256 или выше")
	}

	if strings.Contains(algoName, "MD5") {
		return fmt.Errorf("алгоритм MD5 запрещен")
	}

	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return nil
	default:
		return nil
	}
}

// ValidatePathLength проверяет ограничение длины пути
func (p *PolicyConfig) ValidatePathLength(pathLen int, isIntermediate bool) error {
	if isIntermediate && pathLen > 0 {
		return fmt.Errorf("промежуточные CA не могут выпускать другие CA (pathLen должно быть 0), получено: %d", pathLen)
	}
	return nil
}

// ValidateKeyUsage проверяет использование ключа
func (p *PolicyConfig) ValidateKeyUsage(keyUsage x509.KeyUsage, extendedUsages []x509.ExtKeyUsage, templateType templates.TemplateType) error {
	if keyUsage&x509.KeyUsageDigitalSignature == 0 && templateType != templates.CodeSigning {
	}

	switch templateType {
	case templates.Server:
		if keyUsage&x509.KeyUsageKeyEncipherment == 0 && keyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("серверный сертификат должен поддерживать KeyEncipherment или DigitalSignature")
		}
	case templates.Client:
		if keyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("клиентский сертификат должен поддерживать DigitalSignature")
		}
	case templates.CodeSigning:
		if keyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("сертификат подписи кода должен поддерживать DigitalSignature")
		}
	}

	return nil
}

// ValidateWildcardForCA проверяет wildcard для CA сертификатов
func (p *PolicyConfig) ValidateWildcardForCA(sans []templates.SAN, isCA bool) error {
	if !isCA {
		return nil
	}

	if p.RejectWildcards {
		for _, san := range sans {
			if san.Type == "dns" && strings.Contains(san.Value, "*") {
				return fmt.Errorf("wildcard SAN (%s) запрещен для CA сертификатов", san.Value)
			}
		}
	}
	return nil
}
