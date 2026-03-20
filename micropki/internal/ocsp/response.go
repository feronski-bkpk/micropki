package ocsp

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"
)

// ResponseBuilder строит OCSP-ответ
type ResponseBuilder struct {
	config *ResponseConfig
}

// NewResponseBuilder создаёт новый строитель ответов
func NewResponseBuilder(config *ResponseConfig) *ResponseBuilder {
	return &ResponseBuilder{
		config: config,
	}
}

// Build создаёт OCSP-ответ
func (b *ResponseBuilder) Build() ([]byte, error) {
	if len(b.config.Request.RequestList) == 0 {
		return nil, NewOCSPError(ResponseStatusMalformedRequest, "пустой запрос")
	}

	responses := make([]responseData, 0, len(b.config.Request.RequestList))

	for _, reqEntry := range b.config.Request.RequestList {
		resp, err := b.buildSingleResponse(&reqEntry)
		if err != nil {
			return nil, err
		}
		responses = append(responses, *resp)
	}

	responderID, err := b.buildResponderID()
	if err != nil {
		return nil, err
	}

	responseExtensions := b.buildResponseExtensions()

	tbsData := TBSResponseData{
		Version:            0,
		ResponderID:        *responderID,
		ProducedAt:         b.config.ProducedAt,
		Responses:          responses,
		ResponseExtensions: responseExtensions,
	}

	tbsDER, err := asn1.Marshal(tbsData)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusInternalError, fmt.Sprintf("ошибка маршалинга TBS: %v", err))
	}

	var signature []byte
	var signatureAlgorithm pkix.AlgorithmIdentifier

	switch key := b.config.ResponderKey.(type) {
	case crypto.Signer:
		hash := crypto.SHA256
		h := hash.New()
		h.Write(tbsDER)
		hashed := h.Sum(nil)

		signature, err = key.Sign(rand.Reader, hashed, hash)
		if err != nil {
			return nil, NewOCSPError(ResponseStatusInternalError, fmt.Sprintf("ошибка подписи: %v", err))
		}
		signatureAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		}
	default:
		return nil, NewOCSPError(ResponseStatusInternalError, "неподдерживаемый тип ключа")
	}

	basicResp := BasicOCSPResponse{
		TBSResponseData:    tbsDER,
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
		Certs:              b.buildCerts(),
	}

	basicDER, err := asn1.Marshal(basicResp)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusInternalError, fmt.Sprintf("ошибка маршалинга Basic: %v", err))
	}

	ocspResp := OCSPResponse{
		ResponseStatus: int(ResponseStatusSuccessful),
		ResponseBytes: responseBytes{
			ResponseType: OIDOCSPBasic,
			Response:     basicDER,
		},
	}

	return asn1.Marshal(ocspResp)
}

// buildSingleResponse создаёт ответ для одного запроса
func (b *ResponseBuilder) buildSingleResponse(reqEntry *RequestEntry) (*responseData, error) {
	certID := reqEntry.CertID
	serialHex := hex.EncodeToString(certID.SerialNumber.Bytes())

	statusResult, err := b.config.DB.GetCertificateStatus(serialHex)
	if err != nil {
		return b.buildUnknownResponse(&certID, reqEntry.Extensions), nil
	}

	resp := &responseData{
		CertID:           certID,
		ThisUpdate:       statusResult.ThisUpdate,
		SingleExtensions: reqEntry.Extensions,
	}

	switch statusResult.Status {
	case StatusGood:
		resp.CertStatus = asn1.RawValue{Tag: asn1.TagNull, Bytes: []byte{}}

	case StatusRevoked:
		revokedInfo := struct {
			RevocationTime time.Time
			Reason         int `asn1:"optional,explicit,tag:0"`
		}{
			RevocationTime: *statusResult.RevocationTime,
		}
		if statusResult.RevocationReason != nil {
			revokedInfo.Reason = *statusResult.RevocationReason
		}
		revokedDER, _ := asn1.Marshal(revokedInfo)
		resp.CertStatus = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      revokedDER,
			IsCompound: true,
		}

	case StatusUnknown:
		return b.buildUnknownResponse(&certID, reqEntry.Extensions), nil
	}

	if statusResult.NextUpdate != nil {
		resp.NextUpdate = *statusResult.NextUpdate
	}

	return resp, nil
}

// buildUnknownResponse создаёт ответ со статусом unknown
func (b *ResponseBuilder) buildUnknownResponse(certID *CertID, exts []pkix.Extension) *responseData {
	return &responseData{
		CertID:           *certID,
		CertStatus:       asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte{}},
		ThisUpdate:       b.config.ProducedAt,
		SingleExtensions: exts,
	}
}

// buildResponderID создаёт идентификатор ответчика (byKey)
func (b *ResponseBuilder) buildResponderID() (*asn1.RawValue, error) {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(b.config.ResponderCert.PublicKey)
	if err != nil {
		return nil, err
	}

	hash := crypto.SHA1.New()
	hash.Write(pubKeyDER)
	keyHash := hash.Sum(nil)

	return &asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      keyHash,
	}, nil
}

// buildResponseExtensions создаёт расширения ответа
func (b *ResponseBuilder) buildResponseExtensions() []pkix.Extension {
	var exts []pkix.Extension

	if nonce := b.getNonceFromRequest(); nonce != nil {
		exts = append(exts, pkix.Extension{
			Id:       OIDOCSPNonce,
			Critical: false,
			Value:    nonce,
		})
	}

	return exts
}

// buildCerts создаёт список дополнительных сертификатов
func (b *ResponseBuilder) buildCerts() []asn1.RawValue {
	if b.config.ResponderCert != nil &&
		!b.config.ResponderCert.Equal(b.config.IssuerCert) {
		return []asn1.RawValue{
			{FullBytes: b.config.ResponderCert.Raw},
		}
	}
	return nil
}

// getNonceFromRequest извлекает nonce из запроса
func (b *ResponseBuilder) getNonceFromRequest() []byte {
	for _, ext := range b.config.Request.Extensions {
		if ext.Id.Equal(OIDOCSPNonce) {
			return ext.Value
		}
	}
	return nil
}

type OCSPResponse struct {
	ResponseStatus int
	ResponseBytes  responseBytes `asn1:"optional,explicit,tag:0"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type BasicOCSPResponse struct {
	TBSResponseData    []byte
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type TBSResponseData struct {
	Version            int
	ResponderID        asn1.RawValue
	ProducedAt         time.Time
	Responses          []responseData
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type responseData struct {
	CertID           CertID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time
	NextUpdate       time.Time        `asn1:"optional,explicit,tag:0"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}
