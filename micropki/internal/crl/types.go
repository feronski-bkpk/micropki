// Package crl реализует функциональность для работы со списками отзыва сертификатов
// согласно RFC 5280. Поддерживает CRL версии 2 (v2) с расширениями.
package crl

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ReasonCode представляет код причины отзыва сертификата
type ReasonCode int

// Константы причин отзыва
const (
	ReasonUnspecified          ReasonCode = 0
	ReasonKeyCompromise        ReasonCode = 1
	ReasonCACompromise         ReasonCode = 2
	ReasonAffiliationChanged   ReasonCode = 3
	ReasonSuperseded           ReasonCode = 4
	ReasonCessationOfOperation ReasonCode = 5
	ReasonCertificateHold      ReasonCode = 6
	// Значение 7 зарезервировано
	ReasonRemoveFromCRL      ReasonCode = 8
	ReasonPrivilegeWithdrawn ReasonCode = 9
	ReasonAACompromise       ReasonCode = 10
)

// String возвращает строковое представление кода причины.
func (r ReasonCode) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonCACompromise:
		return "cACompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	case ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ReasonAACompromise:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// ParseReasonCode преобразует строку в код причины
func ParseReasonCode(s string) (ReasonCode, error) {
	lower := strings.ToLower(s)

	switch lower {
	case "unspecified", "0":
		return ReasonUnspecified, nil
	case "keycompromise", "1":
		return ReasonKeyCompromise, nil
	case "cacompromise", "2":
		return ReasonCACompromise, nil
	case "affiliationchanged", "3":
		return ReasonAffiliationChanged, nil
	case "superseded", "4":
		return ReasonSuperseded, nil
	case "cessationofoperation", "5":
		return ReasonCessationOfOperation, nil
	case "certificatehold", "6":
		return ReasonCertificateHold, nil
	case "removefromcrl", "8":
		return ReasonRemoveFromCRL, nil
	case "privilegewithdrawn", "9":
		return ReasonPrivilegeWithdrawn, nil
	case "aacompromise", "10":
		return ReasonAACompromise, nil
	default:
		return ReasonUnspecified, fmt.Errorf("неподдерживаемый код причины: %s", s)
	}
}

// RevokedCertificate представляет отозванный сертификат для включения в CRL.
type RevokedCertificate struct {
	// SerialNumber - серийный номер отозванного сертификата
	SerialNumber *big.Int
	// RevocationTime - время отзыва в UTC
	RevocationTime time.Time
	// ReasonCode - код причины отзыва (опционально)
	ReasonCode *ReasonCode
}

// CRLConfig содержит параметры для генерации CRL.
type CRLConfig struct {
	// IssuerCert - сертификат центра сертификации, выпускающего CRL
	IssuerCert *x509.Certificate
	// IssuerKey - закрытый ключ центра сертификации для подписи CRL
	IssuerKey interface{}
	// ThisUpdate - время выпуска CRL (по умолчанию: текущее UTC)
	ThisUpdate time.Time
	// NextUpdate - время следующего обновления CRL
	NextUpdate time.Time
	// RevokedCerts - список отозванных сертификатов
	RevokedCerts []RevokedCertificate
	// CRLNumber - монотонно возрастающий номер CRL
	CRLNumber int
	// IncludeReasonExtensions - включать ли расширения с причинами отзыва
	IncludeReasonExtensions bool
}

// CRLInfo содержит метаданные CRL для хранения в базе данных.
type CRLInfo struct {
	// CASubject - DN центра сертификации
	CASubject string
	// CRLNumber - текущий номер CRL
	CRLNumber int
	// LastGenerated - время последней генерации
	LastGenerated time.Time
	// NextUpdate - запланированное время следующего обновления
	NextUpdate time.Time
	// CRLPath - путь к файлу CRL
	CRLPath string
	// ThisUpdate - время ThisUpdate из CRL
	ThisUpdate time.Time
	// RevokedCount - количество отозванных сертификатов
	RevokedCount int
}

// CRL представляет полный список отзыва с метаданными.
type CRL struct {
	// RawCRL - сырой CRL в DER-формате
	RawCRL []byte
	// PEM - CRL в PEM-формате
	PEM string
	// Info - метаданные CRL
	Info *CRLInfo
}

// ToPEM конвертирует DER CRL в PEM-формат.
func ToPEM(derCRL []byte) string {
	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: derCRL,
	}
	return string(pem.EncodeToMemory(block))
}

// ParsePEM парсит CRL из PEM-формата.
func ParsePEM(pemData []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}
	if block.Type != "X509 CRL" {
		return nil, fmt.Errorf("неверный тип PEM: %s (ожидался X509 CRL)", block.Type)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать CRL: %w", err)
	}
	return crl, nil
}
