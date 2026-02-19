// Package san implements Subject Alternative Name parsing and validation
// according to RFC 5280.
package san

import (
	"fmt"
	"net"
	"strings"

	"micropki/micropki/internal/templates"
)

// SANType defines the type of Subject Alternative Name
type SANType string

const (
	DNS   SANType = "dns"
	IP    SANType = "ip"
	Email SANType = "email"
	URI   SANType = "uri"
)

// SAN represents a parsed Subject Alternative Name
type SAN struct {
	Type  SANType
	Value string
}

// ParseSAN parses a string of format "type:value"
// Supported types: dns, ip, email, uri
func ParseSAN(san string) (SAN, error) {
	parts := strings.SplitN(san, ":", 2)
	if len(parts) != 2 {
		return SAN{}, fmt.Errorf("invalid SAN format: %s (expected type:value)", san)
	}

	sanType := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	if value == "" {
		return SAN{}, fmt.Errorf("empty SAN value for type %s", sanType)
	}

	// Validate based on type
	switch sanType {
	case "dns":
		// DNS validation - basic check for now
		if len(value) == 0 {
			return SAN{}, fmt.Errorf("empty DNS name")
		}
	case "ip":
		if net.ParseIP(value) == nil {
			return SAN{}, fmt.Errorf("invalid IP address: %s", value)
		}
	case "email":
		// Basic email validation - should contain @
		if !strings.Contains(value, "@") {
			return SAN{}, fmt.Errorf("invalid email address: %s", value)
		}
	case "uri":
		// Basic URI validation - should start with scheme
		if !strings.Contains(value, "://") {
			return SAN{}, fmt.Errorf("invalid URI: %s (should contain scheme)", value)
		}
	default:
		return SAN{}, fmt.Errorf("unsupported SAN type: %s (supported: dns, ip, email, uri)", sanType)
	}

	return SAN{
		Type:  SANType(sanType),
		Value: value,
	}, nil
}

// ValidateSANTypes checks if the provided SANs are compatible with the template
func ValidateSANTypes(tmplType templates.TemplateType, sans []string) error {
	if len(sans) == 0 {
		// Server certificates require at least one SAN
		if tmplType == templates.Server {
			return fmt.Errorf("server certificate requires at least one SAN (DNS or IP)")
		}
		// Client and CodeSigning can have no SANs
		return nil
	}

	// Parse and validate each SAN
	parsedSANs := make([]SAN, 0, len(sans))
	for _, san := range sans {
		parsed, err := ParseSAN(san)
		if err != nil {
			return fmt.Errorf("invalid SAN '%s': %w", san, err)
		}
		parsedSANs = append(parsedSANs, parsed)
	}

	// Template-specific validations
	switch tmplType {
	case templates.Server:
		// Server must have at least one DNS or IP
		hasDNSorIP := false
		for _, san := range parsedSANs {
			if san.Type == DNS || san.Type == IP {
				hasDNSorIP = true
				break
			}
		}
		if !hasDNSorIP {
			return fmt.Errorf("server certificate requires at least one DNS or IP SAN")
		}

	case templates.Client:
		// Client can have any types, no additional validation needed

	case templates.CodeSigning:
		// Code signing should not have IP or Email SANs
		for _, san := range parsedSANs {
			if san.Type == IP {
				return fmt.Errorf("code signing certificate cannot have IP SANs")
			}
			if san.Type == Email {
				return fmt.Errorf("code signing certificate cannot have Email SANs")
			}
		}
	}

	return nil
}

// ExtractSANs extracts SANs from a certificate request or certificate
// This is a helper function to get SANs in a consistent format
func ExtractSANs(dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []string) []SAN {
	var sans []SAN

	for _, dns := range dnsNames {
		sans = append(sans, SAN{Type: DNS, Value: dns})
	}

	for _, ip := range ipAddresses {
		sans = append(sans, SAN{Type: IP, Value: ip.String()})
	}

	for _, email := range emailAddresses {
		sans = append(sans, SAN{Type: Email, Value: email})
	}

	for _, uri := range uris {
		sans = append(sans, SAN{Type: URI, Value: uri})
	}

	return sans
}

// String returns the string representation of a SAN in "type:value" format
func (s SAN) String() string {
	return fmt.Sprintf("%s:%s", s.Type, s.Value)
}
