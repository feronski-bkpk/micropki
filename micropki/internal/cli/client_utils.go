package cli

import (
	"net"
	"net/url"

	"micropki/micropki/internal/templates"
)

// getDNSNames извлекает DNS имена из SAN
func getDNSNames(sans []templates.SAN) []string {
	var result []string
	for _, san := range sans {
		if san.Type == "dns" {
			result = append(result, san.Value)
		}
	}
	return result
}

// getIPAddresses извлекает IP адреса из SAN
func getIPAddresses(sans []templates.SAN) []net.IP {
	var result []net.IP
	for _, san := range sans {
		if san.Type == "ip" {
			ip := net.ParseIP(san.Value)
			if ip != nil {
				result = append(result, ip)
			}
		}
	}
	return result
}

// getEmailAddresses извлекает email адреса из SAN
func getEmailAddresses(sans []templates.SAN) []string {
	var result []string
	for _, san := range sans {
		if san.Type == "email" {
			result = append(result, san.Value)
		}
	}
	return result
}

// getURIs извлекает URI из SAN
func getURIs(sans []templates.SAN) []*url.URL {
	var result []*url.URL
	for _, san := range sans {
		if san.Type == "uri" {
			if u, err := url.Parse(san.Value); err == nil {
				result = append(result, u)
			}
		}
	}
	return result
}

// sanitizeFilename удаляет символы, небезопасные для имён файлов
func sanitizeFilename(name string) string {
	result := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
