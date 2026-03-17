package ocsp

import (
	"testing"
)

func TestOCSPResponseStatusString(t *testing.T) {
	tests := []struct {
		status OCSPResponseStatus
		want   string
	}{
		{ResponseStatusSuccessful, "successful"},
		{ResponseStatusMalformedRequest, "malformedRequest"},
		{ResponseStatusInternalError, "internalError"},
		{ResponseStatusTryLater, "tryLater"},
		{ResponseStatusSigRequired, "sigRequired"},
		{ResponseStatusUnauthorized, "unauthorized"},
		{OCSPResponseStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("OCSPResponseStatus.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestCertStatusString(t *testing.T) {
	tests := []struct {
		status CertStatus
		want   string
	}{
		{StatusGood, "good"},
		{StatusRevoked, "revoked"},
		{StatusUnknown, "unknown"},
		{CertStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("CertStatus.String() = %v, want %v", got, tt.want)
		}
	}
}
