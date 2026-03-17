package ocsp

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
)

// ASN.1 структуры для парсинга запроса
type algId struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type certID struct {
	HashAlgorithm  algId
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type reqCert struct {
	CertID certID `asn1:"explicit,tag:0"`
}

type singleRequest struct {
	ReqCert reqCert `asn1:"explicit,tag:0"`
}

type requestList struct {
	Requests []singleRequest `asn1:"explicit,tag:2"`
}

type tbsRequest struct {
	Version       int           `asn1:"default:0,explicit,tag:0"`
	RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`
	RequestList   requestList   `asn1:"explicit,tag:2"`
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

// ParseRequest разбирает DER-encoded OCSP запрос
func ParseRequest(der []byte) (*Request, error) {
	var req ocspRequest
	_, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusMalformedRequest,
			fmt.Sprintf("не удалось разобрать запрос: %v", err))
	}

	if len(req.TBSRequest.RequestList.Requests) == 0 {
		fmt.Printf("No certificates in request\n")
		return nil, NewOCSPError(ResponseStatusMalformedRequest,
			"запрос не содержит сертификатов")
	}

	result := &Request{
		Version:     req.TBSRequest.Version,
		RequestList: make([]RequestEntry, len(req.TBSRequest.RequestList.Requests)),
		Extensions:  []pkix.Extension{},
	}

	for i, entry := range req.TBSRequest.RequestList.Requests {
		result.RequestList[i] = RequestEntry{
			CertID: CertID{
				HashAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: entry.ReqCert.CertID.HashAlgorithm.Algorithm,
				},
				IssuerNameHash: entry.ReqCert.CertID.IssuerNameHash,
				IssuerKeyHash:  entry.ReqCert.CertID.IssuerKeyHash,
				SerialNumber:   entry.ReqCert.CertID.SerialNumber,
			},
		}
		fmt.Printf("  CertID %d: Serial=%X\n", i, entry.ReqCert.CertID.SerialNumber)
	}

	return result, nil
}

// GetNonce извлекает nonce из расширений запроса
func (r *Request) GetNonce() ([]byte, error) {
	return nil, nil
}

// Validate проверяет корректность запроса
func (r *Request) Validate() error {
	if r.Version != 0 {
		return NewOCSPError(ResponseStatusMalformedRequest,
			fmt.Sprintf("неподдерживаемая версия OCSP: %d (ожидалась 0)", r.Version))
	}

	if len(r.RequestList) == 0 {
		return NewOCSPError(ResponseStatusMalformedRequest,
			"запрос не содержит ни одного CertID")
	}

	return nil
}

// ComputeIssuerHashes вычисляет хеши для издателя
func ComputeIssuerHashes(issuer *x509.Certificate) (nameHash, keyHash []byte, err error) {
	derName, err := asn1.Marshal(issuer.RawSubject)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось маршалировать DN издателя: %w", err)
	}
	hash := sha1.Sum(derName)
	nameHash = hash[:]

	pubKeyDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось маршалировать публичный ключ: %w", err)
	}
	hash = sha1.Sum(pubKeyDER)
	keyHash = hash[:]

	return nameHash, keyHash, nil
}

// VerifyCertID проверяет соответствие CertID указанному издателю
func VerifyCertID(certID *CertID, issuer *x509.Certificate) (bool, error) {
	expectedNameHash, expectedKeyHash, err := ComputeIssuerHashes(issuer)
	if err != nil {
		return false, err
	}

	if !certID.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}) &&
		!certID.HashAlgorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		return false, fmt.Errorf("неподдерживаемый алгоритм хеширования: %v", certID.HashAlgorithm.Algorithm)
	}

	if !compareHashes(certID.IssuerNameHash, expectedNameHash) {
		return false, nil
	}

	if !compareHashes(certID.IssuerKeyHash, expectedKeyHash) {
		return false, nil
	}

	return true, nil
}

func compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func (c *CertID) String() string {
	serialHex := hex.EncodeToString(c.SerialNumber.Bytes())
	if len(serialHex) > 16 {
		serialHex = serialHex[:8] + "..." + serialHex[len(serialHex)-8:]
	}
	return fmt.Sprintf("Serial=%s", serialHex)
}
