package revocation

import (
	"crypto/x509"
)

// CDPParser извлекает информацию из расширения CRL Distribution Points
type CDPParser struct{}

// ParseCDP извлекает URL точек распространения CRL
func (p *CDPParser) ParseCDP(cert *x509.Certificate) ([]string, error) {
	var urls []string

	for _, cdp := range cert.CRLDistributionPoints {
		if cdp != "" {
			urls = append(urls, cdp)
		}
	}

	return urls, nil
}

// HasCRLDistributionPoint проверяет, есть ли у сертификата CDP
func (p *CDPParser) HasCRLDistributionPoint(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}
