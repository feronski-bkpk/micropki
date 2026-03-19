package ocsp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// OID для OCSP
var (
	OIDOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

	// OIDOCSPBasic - OID для базового ответа (1.3.6.1.5.5.7.48.1.1)
	OIDOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	// OIDOCSPSigning - OID для EKU OCSP signing (1.3.6.1.5.5.7.3.9)
	OIDOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// OCSPResponseStatus определяет статус ответа OCSP
type OCSPResponseStatus int

const (
	ResponseStatusSuccessful       OCSPResponseStatus = 0 // ответ имеет действительную подтверждённую информацию
	ResponseStatusMalformedRequest OCSPResponseStatus = 1 // неверный формат запроса
	ResponseStatusInternalError    OCSPResponseStatus = 2 // внутренняя ошибка ответчика
	ResponseStatusTryLater         OCSPResponseStatus = 3 // попробуйте позже
	ResponseStatusSigRequired      OCSPResponseStatus = 5 // требуется подпись
	ResponseStatusUnauthorized     OCSPResponseStatus = 6 // запрос не авторизован
)

// String возвращает строковое представление статуса ответа
func (s OCSPResponseStatus) String() string {
	switch s {
	case ResponseStatusSuccessful:
		return "successful"
	case ResponseStatusMalformedRequest:
		return "malformedRequest"
	case ResponseStatusInternalError:
		return "internalError"
	case ResponseStatusTryLater:
		return "tryLater"
	case ResponseStatusSigRequired:
		return "sigRequired"
	case ResponseStatusUnauthorized:
		return "unauthorized"
	default:
		return "unknown"
	}
}

// CertStatus определяет статус сертификата
type CertStatus int

const (
	StatusGood    CertStatus = 0 // сертификат не отозван
	StatusRevoked CertStatus = 1 // сертификат отозван
	StatusUnknown CertStatus = 2 // статус неизвестен
)

// String возвращает строковое представление статуса сертификата
func (s CertStatus) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	case StatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// CertID представляет идентификатор сертификата
type CertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// RequestEntry представляет отдельную запись в запросе
type RequestEntry struct {
	CertID     CertID
	Extensions []pkix.Extension
}

// Request представляет OCSP-запрос
type Request struct {
	Version       int
	RequestorName *asn1.RawValue
	RequestList   []RequestEntry
	Extensions    []pkix.Extension
}

// StatusChecker определяет интерфейс для проверки статуса сертификатов
type StatusChecker interface {
	GetCertificateStatus(serialHex string) (*StatusResult, error)
	GetIssuerByHashes(nameHash, keyHash []byte) (*x509.Certificate, error)
}

// StatusResult содержит результат проверки статуса сертификата
type StatusResult struct {
	Status           CertStatus
	RevocationTime   *time.Time
	RevocationReason *int
	ThisUpdate       time.Time
	NextUpdate       *time.Time
}

// ResponseConfig содержит параметры для формирования OCSP-ответа
type ResponseConfig struct {
	Request           *Request
	IssuerCert        *x509.Certificate
	ResponderCert     *x509.Certificate
	ResponderKey      interface{}
	DB                StatusChecker
	CacheTTL          int // в секундах
	ProducedAt        time.Time
	IncludeNextUpdate bool
}

// OCSPError представляет ошибку OCSP с соответствующим статусом ответа
type OCSPError struct {
	Status OCSPResponseStatus
	Msg    string
}

func (e *OCSPError) Error() string {
	return fmt.Sprintf("OCSP error (%s): %s", e.Status.String(), e.Msg)
}

// NewOCSPError создаёт новую ошибку OCSP
func NewOCSPError(status OCSPResponseStatus, msg string) *OCSPError {
	return &OCSPError{
		Status: status,
		Msg:    msg,
	}
}
