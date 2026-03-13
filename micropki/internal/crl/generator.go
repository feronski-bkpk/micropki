package crl

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// GenerateCRL создает новый CRL согласно RFC 5280.
// Функция поддерживает CRL версии 2 (v2) с расширениями:
//   - Authority Key Identifier (AKI)
//   - CRL Number
//   - Reason Code (для отдельных записей, если запрошено)
func GenerateCRL(cfg *CRLConfig) (*CRL, error) {
	thisUpdate := cfg.ThisUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().UTC()
	}

	if cfg.NextUpdate.IsZero() {
		return nil, fmt.Errorf("NextUpdate обязательно для CRL")
	}

	revokedCerts := make([]pkix.RevokedCertificate, 0, len(cfg.RevokedCerts))
	for _, rc := range cfg.RevokedCerts {
		entry := pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevocationTime,
		}

		if cfg.IncludeReasonExtensions && rc.ReasonCode != nil {
			reasonBytes, err := asn1.Marshal(asn1.Enumerated(*rc.ReasonCode))
			if err == nil {
				entry.Extensions = append(entry.Extensions, pkix.Extension{
					Id:       []int{2, 5, 29, 21},
					Critical: false,
					Value:    reasonBytes,
				})
			}
		}

		revokedCerts = append(revokedCerts, entry)
	}

	template := &x509.RevocationList{
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(int64(cfg.CRLNumber)),
		ThisUpdate:          thisUpdate,
		NextUpdate:          cfg.NextUpdate,
	}

	var aki []byte
	for _, ext := range cfg.IssuerCert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 35}) {
			aki = ext.Value
			break
		}
	}
	if aki != nil {
	}

	signer, ok := cfg.IssuerKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ключ подписи не реализует crypto.Signer")
	}

	derCRL, err := x509.CreateRevocationList(
		nil,            // rand
		template,       // template
		cfg.IssuerCert, // issuer
		signer,         // signerKey
	)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать CRL: %w", err)
	}

	parsedCRL, err := x509.ParseRevocationList(derCRL)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать созданный CRL: %w", err)
	}

	if err := parsedCRL.CheckSignatureFrom(cfg.IssuerCert); err != nil {
		return nil, fmt.Errorf("проверка подписи CRL не пройдена: %w", err)
	}

	info := &CRLInfo{
		CASubject:     cfg.IssuerCert.Subject.String(),
		CRLNumber:     cfg.CRLNumber,
		LastGenerated: time.Now().UTC(),
		NextUpdate:    cfg.NextUpdate,
		ThisUpdate:    thisUpdate,
		RevokedCount:  len(cfg.RevokedCerts),
	}

	return &CRL{
		RawCRL: derCRL,
		PEM:    ToPEM(derCRL),
		Info:   info,
	}, nil
}

// VerifyCRL проверяет подпись и целостность CRL.
func VerifyCRL(crlPEM []byte, issuerCert *x509.Certificate) error {
	crl, err := ParsePEM(crlPEM)
	if err != nil {
		return err
	}

	if err := crl.CheckSignatureFrom(issuerCert); err != nil {
		return fmt.Errorf("проверка подписи CRL не пройдена: %w", err)
	}

	return nil
}
