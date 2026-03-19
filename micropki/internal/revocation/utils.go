package revocation

import (
	"crypto/x509"
	"strings"
)

// getOCSPURL извлекает URL OCSP ответчика из расширения AIA
func getOCSPURL(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	for _, url := range cert.OCSPServer {
		if url != "" {
			return url
		}
	}

	return ""
}

// hasOCSPResponder проверяет, есть ли у сертификата OCSP ответчик
func hasOCSPResponder(cert *x509.Certificate) bool {
	return len(cert.OCSPServer) > 0 && cert.OCSPServer[0] != ""
}

// hasCRLDistributionPoint проверяет, есть ли у сертификата CDP
func hasCRLDistributionPoint(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}

func extractOCSPURLFromAIA(cert *x509.Certificate) string {
	return getOCSPURL(cert)
}

// normalizeCRLURL нормализует URL CRL
func normalizeCRLURL(url string) string {
	url = strings.TrimSpace(url)

	if strings.HasPrefix(url, "URI:") {
		url = strings.TrimPrefix(url, "URI:")
	}

	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}

	return url
}
