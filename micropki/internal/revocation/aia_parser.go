package revocation

import (
	"crypto/x509"
)

// AIAParser извлекает информацию из расширения Authority Information Access
type AIAParser struct{}

// ParseAIA извлекает OCSP URL из сертификата
func (p *AIAParser) ParseAIA(cert *x509.Certificate) ([]string, error) {
	var urls []string

	for _, url := range cert.OCSPServer {
		if url != "" {
			urls = append(urls, url)
		}
	}

	return urls, nil
}

// HasOCSPResponder проверяет, есть ли у сертификата OCSP ответчик
func (p *AIAParser) HasOCSPResponder(cert *x509.Certificate) bool {
	return len(cert.OCSPServer) > 0 && cert.OCSPServer[0] != ""
}
