package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// ASN.1 структуры для построения ответа
type respCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  *big.Int
}

type respRevokedInfo struct {
	RevocationTime time.Time
	Reason         int `asn1:"optional,explicit,tag:0"`
}

type respSingleResponse struct {
	CertID           respCertID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time
	NextUpdate       time.Time        `asn1:"optional,explicit,tag:0"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type respResponderID struct {
	ByName asn1.RawValue `asn1:"optional,explicit,tag:1"`
	ByKey  asn1.RawValue `asn1:"optional,explicit,tag:2"`
}

type respResponseData struct {
	Version            int `asn1:"default:0,explicit,tag:0"`
	ResponderID        respResponderID
	ProducedAt         time.Time
	Responses          []respSingleResponse
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type respBasicResponse struct {
	TBSResponseData    respResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,tag:0"`
}

type respResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type respResponse struct {
	Status       int
	ResponseData respResponseBytes `asn1:"optional,explicit,tag:0"`
}

// ResponseBuilder строит OCSP-ответы
type ResponseBuilder struct {
	config *ResponseConfig
}

// NewResponseBuilder создаёт новый построитель ответов
func NewResponseBuilder(config *ResponseConfig) *ResponseBuilder {
	return &ResponseBuilder{
		config: config,
	}
}

// Build строит OCSP-ответ
func (b *ResponseBuilder) Build() ([]byte, error) {
	if b.config.Request == nil {
		return b.buildErrorResponse(ResponseStatusInternalError)
	}

	if err := b.config.Request.Validate(); err != nil {
		if ocspErr, ok := err.(*OCSPError); ok {
			return b.buildErrorResponse(ocspErr.Status)
		}
		return b.buildErrorResponse(ResponseStatusMalformedRequest)
	}

	nonce, _ := b.config.Request.GetNonce()

	responses := make([]respSingleResponse, 0, len(b.config.Request.RequestList))

	for _, entry := range b.config.Request.RequestList {
		single, err := b.buildSingleResponse(&entry, nonce)
		if err != nil {
			continue
		}
		responses = append(responses, *single)
	}

	if len(responses) == 0 {
		return b.buildErrorResponse(ResponseStatusInternalError)
	}

	responderID, err := b.buildResponderID()
	if err != nil {
		return nil, err
	}

	respData := respResponseData{
		Version:     0,
		ResponderID: *responderID,
		ProducedAt:  b.config.ProducedAt.UTC(),
		Responses:   responses,
	}

	if nonce != nil {
		nonceExt, err := b.buildNonceExtension(nonce)
		if err != nil {
			return nil, err
		}
		respData.ResponseExtensions = append(respData.ResponseExtensions, *nonceExt)
	}

	dataDER, err := asn1.Marshal(respData)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать ResponseData: %w", err)
	}

	signature, err := b.signResponse(dataDER)
	if err != nil {
		return nil, err
	}

	basicResp := respBasicResponse{
		TBSResponseData:    respData,
		SignatureAlgorithm: signature.Algorithm,
		Signature:          signature.Signature,
	}

	basicDER, err := asn1.Marshal(basicResp)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать BasicResponse: %w", err)
	}

	resp := respResponse{
		Status:       int(ResponseStatusSuccessful),
		ResponseData: respResponseBytes{ResponseType: OIDOCSPBasic, Response: basicDER},
	}

	return asn1.Marshal(resp)
}

// buildSingleResponse строит ответ для одного сертификата
func (b *ResponseBuilder) buildSingleResponse(entry *RequestEntry, requestNonce []byte) (*respSingleResponse, error) {
	certID := respCertID{
		HashAlgorithm: entry.CertID.HashAlgorithm,
		NameHash:      entry.CertID.IssuerNameHash,
		KeyHash:       entry.CertID.IssuerKeyHash,
		SerialNumber:  entry.CertID.SerialNumber,
	}

	issuer, err := b.config.DB.GetIssuerByHashes(certID.NameHash, certID.KeyHash)
	if err != nil {
		return b.buildUnknownResponse(&certID)
	}

	match, err := VerifyCertID(&entry.CertID, issuer)
	if err != nil || !match {
		return b.buildUnknownResponse(&certID)
	}

	status, err := b.config.DB.GetCertificateStatus(
		certID.NameHash,
		certID.KeyHash,
		certID.SerialNumber,
	)
	if err != nil {
		return b.buildUnknownResponse(&certID)
	}

	var certStatus asn1.RawValue
	switch status.Status {
	case StatusGood:
		certStatus = asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: false}
	case StatusRevoked:
		info := respRevokedInfo{
			RevocationTime: status.RevocationTime.UTC(),
		}
		if status.RevocationReason != nil {
			info.Reason = *status.RevocationReason
		}
		infoDER, err := asn1.Marshal(info)
		if err != nil {
			return nil, err
		}
		certStatus = asn1.RawValue{
			Tag:        1,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      infoDER,
		}
	case StatusUnknown:
		certStatus = asn1.RawValue{Tag: 2, Class: asn1.ClassContextSpecific, IsCompound: false}
	}

	single := respSingleResponse{
		CertID:     certID,
		CertStatus: certStatus,
		ThisUpdate: status.ThisUpdate.UTC(),
	}

	if b.config.IncludeNextUpdate && b.config.CacheTTL > 0 {
		single.NextUpdate = status.ThisUpdate.Add(time.Duration(b.config.CacheTTL) * time.Second).UTC()
	}

	return &single, nil
}

// buildUnknownResponse строит ответ со статусом unknown
func (b *ResponseBuilder) buildUnknownResponse(certID *respCertID) (*respSingleResponse, error) {
	certStatus := asn1.RawValue{Tag: 2, Class: asn1.ClassContextSpecific, IsCompound: false}

	return &respSingleResponse{
		CertID:     *certID,
		CertStatus: certStatus,
		ThisUpdate: time.Now().UTC(),
	}, nil
}

// buildResponderID строит идентификатор ответчика
func (b *ResponseBuilder) buildResponderID() (*respResponderID, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(b.config.ResponderCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать публичный ключ: %w", err)
	}

	keyHash := sha1.Sum(pubKeyDER)

	var id respResponderID
	id.ByKey = asn1.RawValue{
		Tag:   2,
		Class: asn1.ClassContextSpecific,
		Bytes: keyHash[:],
	}

	return &id, nil
}

// buildNonceExtension создаёт расширение nonce
func (b *ResponseBuilder) buildNonceExtension(nonce []byte) (*pkix.Extension, error) {
	nonceDER, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать nonce: %w", err)
	}

	return &pkix.Extension{
		Id:    OIDOCSPNonce,
		Value: nonceDER,
	}, nil
}

// SignatureResult содержит результат подписи
type SignatureResult struct {
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// signResponse подписывает ResponseData
func (b *ResponseBuilder) signResponse(data []byte) (*SignatureResult, error) {
	var hash crypto.Hash
	var algo pkix.AlgorithmIdentifier

	switch b.config.ResponderCert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		hash = crypto.SHA256
		algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		}
	case x509.SHA384WithRSA:
		hash = crypto.SHA384
		algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12},
		}
	case x509.SHA512WithRSA:
		hash = crypto.SHA512
		algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13},
		}
	case x509.ECDSAWithSHA256:
		hash = crypto.SHA256
		algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		}
	case x509.ECDSAWithSHA384:
		hash = crypto.SHA384
		algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3},
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм подписи: %v",
			b.config.ResponderCert.SignatureAlgorithm)
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	signer, ok := b.config.ResponderKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ключ не поддерживает crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		return nil, fmt.Errorf("не удалось подписать ответ: %w", err)
	}

	return &SignatureResult{
		Algorithm: algo,
		Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}, nil
}

// buildErrorResponse строит ответ с ошибкой
func (b *ResponseBuilder) buildErrorResponse(status OCSPResponseStatus) ([]byte, error) {
	resp := respResponse{
		Status: int(status),
	}
	return asn1.Marshal(resp)
}

// EncodeResponseToPEM кодирует DER ответ в PEM
func EncodeResponseToPEM(der []byte) []byte {
	block := &pem.Block{
		Type:  "OCSP RESPONSE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block)
}
