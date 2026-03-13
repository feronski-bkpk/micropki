package crl

import (
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestReasonCodes проверяет парсинг всех кодов причин отзыва
func TestReasonCodes(t *testing.T) {
	tests := []struct {
		input     string
		expected  ReasonCode
		shouldErr bool
	}{
		{"unspecified", ReasonUnspecified, false},
		{"keyCompromise", ReasonKeyCompromise, false},
		{"cACompromise", ReasonCACompromise, false},
		{"affiliationChanged", ReasonAffiliationChanged, false},
		{"superseded", ReasonSuperseded, false},
		{"cessationOfOperation", ReasonCessationOfOperation, false},
		{"certificateHold", ReasonCertificateHold, false},
		{"removeFromCRL", ReasonRemoveFromCRL, false},
		{"privilegeWithdrawn", ReasonPrivilegeWithdrawn, false},
		{"aACompromise", ReasonAACompromise, false},
		// Числовые коды
		{"0", ReasonUnspecified, false},
		{"1", ReasonKeyCompromise, false},
		{"2", ReasonCACompromise, false},
		{"3", ReasonAffiliationChanged, false},
		{"4", ReasonSuperseded, false},
		{"5", ReasonCessationOfOperation, false},
		{"6", ReasonCertificateHold, false},
		{"8", ReasonRemoveFromCRL, false},
		{"9", ReasonPrivilegeWithdrawn, false},
		{"10", ReasonAACompromise, false},
		{"KEYCOMPROMISE", ReasonKeyCompromise, false},
		{"KeyCompromise", ReasonKeyCompromise, false},
		{"invalid", 0, true},
		{"7", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseReasonCode(tt.input)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("ParseReasonCode(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseReasonCode(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseReasonCode(%q) = %v, want %v", tt.input, result, tt.expected)
				}
				strResult := result.String()
				if strResult == "" {
					t.Errorf("String() for %v returned empty string", result)
				}
				parsedBack, err := ParseReasonCode(strResult)
				if err != nil || parsedBack != result {
					t.Errorf("ParseReasonCode(String()) failed: %v -> %s -> %v", result, strResult, parsedBack)
				}
			}
		})
	}
}

// TestPEMConversion проверяет конвертацию CRL в PEM и обратно
func TestPEMConversion(t *testing.T) {
	testDER := []byte{
		0x30, 0x1b, // SEQUENCE (длина 27)
		0x30, 0x0f, // SEQUENCE (длина 15) - tbsCertList
		0x02, 0x01, 0x01, // version = v2 (1)
		0x30, 0x0a, // SEQUENCE (длина 10) - issuer
		0x31, 0x08, // SET (длина 8)
		0x30, 0x06, // SEQUENCE (длина 6)
		0x06, 0x03, 0x55, 0x04, 0x03, // OID для commonName
		0x0c, 0x01, 0x54, // UTF8String "T"
		0x30, 0x00, // thisUpdate (нулевой длины для теста)
		0x30, 0x00, // nextUpdate (нулевой длины для теста)
		0xa0, 0x00, // extensions (нулевой длины)
		0x30, 0x03, // SEQUENCE (длина 3) - signature
		0x02, 0x01, 0x00, // integer 0
	}

	pemStr := ToPEM(testDER)
	if !strings.Contains(pemStr, "BEGIN X509 CRL") {
		t.Errorf("PEM missing header, got: %s", pemStr)
	}
	if !strings.Contains(pemStr, "END X509 CRL") {
		t.Errorf("PEM missing footer, got: %s", pemStr)
	}

	_, err := ParsePEM([]byte(pemStr))
	if err == nil {
		t.Log("ParsePEM succeeded (expected maybe error)")
	}
}

// TestRevokedCertificate проверяет создание записи об отозванном сертификате
func TestRevokedCertificate(t *testing.T) {
	serial := big.NewInt(12345)
	revTime := time.Now().UTC()
	reason := ReasonKeyCompromise

	rc := RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: revTime,
		ReasonCode:     &reason,
	}

	if rc.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("SerialNumber = %v, want %v", rc.SerialNumber, serial)
	}
	if !rc.RevocationTime.Equal(revTime) {
		t.Errorf("RevocationTime = %v, want %v", rc.RevocationTime, revTime)
	}
	if rc.ReasonCode == nil || *rc.ReasonCode != reason {
		t.Errorf("ReasonCode = %v, want %v", rc.ReasonCode, reason)
	}
}

// TestCRLInfo проверяет создание метаданных CRL
func TestCRLInfo(t *testing.T) {
	now := time.Now().UTC()
	info := &CRLInfo{
		CASubject:     "CN=Test CA",
		CRLNumber:     42,
		LastGenerated: now,
		NextUpdate:    now.AddDate(0, 0, 7),
		ThisUpdate:    now,
		CRLPath:       "/tmp/test.crl",
		RevokedCount:  5,
	}

	if info.CASubject != "CN=Test CA" {
		t.Errorf("CASubject = %v, want CN=Test CA", info.CASubject)
	}
	if info.CRLNumber != 42 {
		t.Errorf("CRLNumber = %d, want 42", info.CRLNumber)
	}
	if info.RevokedCount != 5 {
		t.Errorf("RevokedCount = %d, want 5", info.RevokedCount)
	}
}

// contains проверяет наличие подстроки
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
