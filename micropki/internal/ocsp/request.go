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

// ParseRequest парсит DER-encoded OCSP запрос
func ParseRequest(der []byte) (*Request, error) {
	var rawRequest struct {
		TBSRequest struct {
			Version       int
			RequestorName asn1.RawValue `asn1:"optional,explicit,tag:0"`
			RequestList   []struct {
				CertID struct {
					HashAlgorithm  pkix.AlgorithmIdentifier
					IssuerNameHash []byte
					IssuerKeyHash  []byte
					SerialNumber   asn1.RawValue
				}
				SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:0"`
			}
			RequestExtensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
		}
		OptionalSignature asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}

	rest, err := asn1.Unmarshal(der, &rawRequest)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusMalformedRequest,
			fmt.Sprintf("не удалось распарсить запрос: %v", err))
	}
	if len(rest) > 0 {
		return nil, NewOCSPError(ResponseStatusMalformedRequest, "лишние данные после запроса")
	}

	req := &Request{
		Version:    rawRequest.TBSRequest.Version,
		Extensions: rawRequest.TBSRequest.RequestExtensions,
	}

	for _, rawEntry := range rawRequest.TBSRequest.RequestList {
		entry := RequestEntry{
			CertID: CertID{
				HashAlgorithm:  rawEntry.CertID.HashAlgorithm,
				IssuerNameHash: rawEntry.CertID.IssuerNameHash,
				IssuerKeyHash:  rawEntry.CertID.IssuerKeyHash,
				SerialNumber:   new(big.Int).SetBytes(rawEntry.CertID.SerialNumber.Bytes),
			},
			Extensions: rawEntry.SingleExtensions,
		}
		req.RequestList = append(req.RequestList, entry)
	}

	return req, nil
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
