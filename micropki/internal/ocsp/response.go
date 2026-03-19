package ocsp

import (
	"crypto"
	"crypto/rand"
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

	responses := make([]ResponseData, 0, len(b.config.Request.RequestList))

	for _, reqEntry := range b.config.Request.RequestList {
		resp, err := b.buildSingleResponse(&reqEntry)
		if err != nil {
			return nil, err
		}
		responses = append(responses, *resp)
	}

	basicResp := BasicOCSPResponse{
		TBSResponseData: TBSResponseData{
			Version:            0,
			ResponderID:        b.buildResponderID(),
			ProducedAt:         b.config.ProducedAt,
			Responses:          responses,
			ResponseExtensions: b.buildResponseExtensions(),
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		Signature: asn1.BitString{},
		Certs:     b.buildCerts(),
	}

	signature, err := b.signTBSData(basicResp.TBSResponseData)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusInternalError, fmt.Sprintf("ошибка подписи: %v", err))
	}
	basicResp.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}

	basicDER, err := asn1.Marshal(basicResp)
	if err != nil {
		return nil, NewOCSPError(ResponseStatusInternalError, fmt.Sprintf("ошибка маршалинга: %v", err))
	}

	ocspResp := OCSPResponse{
		ResponseStatus: int(ResponseStatusSuccessful),
		ResponseBytes: &ResponseBytes{
			ResponseType: OIDOCSPBasic,
			Response:     basicDER,
		},
	}

	return asn1.Marshal(ocspResp)
}

// buildSingleResponse создаёт ответ для одного запроса
func (b *ResponseBuilder) buildSingleResponse(reqEntry *RequestEntry) (*ResponseData, error) {
	certID := reqEntry.CertID
	serialHex := hex.EncodeToString(certID.SerialNumber.Bytes())

	statusResult, err := b.config.DB.GetCertificateStatus(serialHex)
	if err != nil {
		return &ResponseData{
			CertID:           certID,
			CertStatus:       StatusUnknown,
			ThisUpdate:       b.config.ProducedAt,
			SingleExtensions: reqEntry.Extensions,
		}, nil
	}

	resp := &ResponseData{
		CertID:           certID,
		CertStatus:       statusResult.Status,
		ThisUpdate:       statusResult.ThisUpdate,
		SingleExtensions: reqEntry.Extensions,
	}

	if statusResult.Status == StatusRevoked {
		resp.RevocationTime = statusResult.RevocationTime
		if statusResult.RevocationReason != nil {
			reasonBytes, _ := asn1.Marshal(asn1.Enumerated(*statusResult.RevocationReason))
			resp.RevocationReason = &pkix.Extension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 21},
				Value: reasonBytes,
			}
		}
	}

	if b.config.IncludeNextUpdate && statusResult.NextUpdate != nil {
		resp.NextUpdate = statusResult.NextUpdate
	}

	return resp, nil
}

// buildResponderID создаёт идентификатор ответчика
func (b *ResponseBuilder) buildResponderID() asn1.RawValue {
	nameBytes, err := asn1.Marshal(b.config.ResponderCert.Subject.ToRDNSequence())
	if err != nil {
		return asn1.RawValue{}
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      nameBytes,
	}
}

// buildResponseExtensions создаёт расширения ответа
func (b *ResponseBuilder) buildResponseExtensions() []pkix.Extension {
	var exts []pkix.Extension

	if nonce := b.getNonceFromRequest(); nonce != nil {
		exts = append(exts, pkix.Extension{
			Id:    OIDOCSPNonce,
			Value: nonce,
		})
	}

	return exts
}

// buildCerts создаёт список дополнительных сертификатов
func (b *ResponseBuilder) buildCerts() []asn1.RawValue {
	if b.config.ResponderCert != nil &&
		!b.config.ResponderCert.Equal(b.config.IssuerCert) {
		certDER, err := asn1.Marshal(b.config.ResponderCert.Raw)
		if err == nil {
			return []asn1.RawValue{
				{FullBytes: certDER},
			}
		}
	}
	return nil
}

// signTBSData подписывает данные ответа
func (b *ResponseBuilder) signTBSData(data TBSResponseData) ([]byte, error) {
	dataDER, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}

	var opts crypto.SignerOpts
	if priv, ok := b.config.ResponderKey.(crypto.Signer); ok {
		opts = crypto.SHA256
		return priv.Sign(rand.Reader, dataDER, opts)
	}

	return nil, fmt.Errorf("неподдерживаемый тип ключа")
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

// OCSPResponse представляет полный OCSP-ответ
type OCSPResponse struct {
	ResponseStatus int
	ResponseBytes  *ResponseBytes `asn1:"optional,explicit,tag:0"`
}

// ResponseBytes содержит данные ответа
type ResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// BasicOCSPResponse представляет базовый OCSP-ответ
type BasicOCSPResponse struct {
	TBSResponseData    TBSResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// TBSResponseData содержит данные для подписи
type TBSResponseData struct {
	Version            int
	ResponderID        asn1.RawValue
	ProducedAt         time.Time
	Responses          []ResponseData
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// ResponseData содержит ответ для одного сертификата
type ResponseData struct {
	CertID           CertID
	CertStatus       CertStatus
	RevocationTime   *time.Time      `asn1:"optional,explicit,tag:0"`
	RevocationReason *pkix.Extension `asn1:"optional,explicit,tag:1"`
	ThisUpdate       time.Time
	NextUpdate       *time.Time       `asn1:"optional,explicit,tag:0"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}
