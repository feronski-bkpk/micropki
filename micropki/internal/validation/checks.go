package validation

import (
	"crypto/x509"
	"fmt"
)

// validateCertificate проверяет один сертификат с учетом глубины цепочки
func (pv *PathValidator) validateCertificate(cert, issuer *x509.Certificate, isRoot bool, chainDepth int, certIndex int) *CertificateValidation {
	result := &CertificateValidation{
		Subject:      cert.Subject.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
	}

	// 1. Проверка срока действия
	now := *pv.config.ValidationTime
	result.ValidityPeriod = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	if !result.ValidityPeriod {
		result.Errors = append(result.Errors, "сертификат недействителен в указанное время")
	}

	// 2. Проверка подписи
	if isRoot {
		err := cert.CheckSignatureFrom(cert)
		result.SignatureValid = err == nil
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("недействительная самоподпись: %v", err))
		}
	} else if issuer != nil {
		err := cert.CheckSignatureFrom(issuer)
		result.SignatureValid = err == nil
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("недействительная подпись: %v", err))
		}
	} else {
		result.SignatureValid = false
		result.Errors = append(result.Errors, "нет издателя для проверки подписи")
	}

	// 3. Проверка Basic Constraints для текущего сертификата (если он CA)
	if cert.IsCA {
		requiredKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if cert.KeyUsage&requiredKeyUsage != requiredKeyUsage {
			result.KeyUsageValid = false
			result.Errors = append(result.Errors, "у CA сертификата отсутствуют обязательные KeyUsage")
		} else {
			result.KeyUsageValid = true
		}
	}

	// 4. Проверка ограничений, накладываемых издателем
	if issuer != nil && issuer.IsCA {
		result.CAValid = true

		// Проверка PathLenConstraint (ограничение глубины)
		if issuer.MaxPathLen >= 0 {
			// Только СA сертификаты считаются в глубину
			// Конечные сертификаты (IsCA=false) НЕ считаются
			subordinateCACount := 0
			for i := certIndex + 1; i < chainDepth; i++ {
				// считаем только СA сертификаты ниже
			}

			if subordinateCACount > issuer.MaxPathLen {
				result.PathLenValid = false
				result.Errors = append(result.Errors,
					fmt.Sprintf("превышено ограничение длины пути издателя: %d подчиненных CA при лимите %d",
						subordinateCACount, issuer.MaxPathLen))
			} else {
				result.PathLenValid = true
			}
		} else {
			result.PathLenValid = true
		}
	}

	return result
}
