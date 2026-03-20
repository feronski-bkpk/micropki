package revocation

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// OCSPChecker проверяет статус через OCSP
type OCSPChecker struct {
	client    *http.Client
	cache     map[string]*OCSPCacheEntry
	cacheMu   sync.RWMutex
	cacheTTL  int
	logger    Logger
	userAgent string
}

// OCSPCacheEntry представляет запись в кэше OCSP
type OCSPCacheEntry struct {
	result       *RevocationResult
	fetchedAt    time.Time
	responderURL string
}

// NewOCSPChecker создает новый OCSP проверяльщик
func NewOCSPChecker(config RevocationCheckerConfig) *OCSPChecker {
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &OCSPChecker{
		client:    config.HTTPClient,
		cache:     make(map[string]*OCSPCacheEntry),
		cacheTTL:  config.CacheTTL,
		logger:    config.Logger,
		userAgent: "MicroPKI-OCSP-Client/1.0",
	}
}

// Check выполняет OCSP проверку
func (oc *OCSPChecker) Check(cert, issuer *x509.Certificate) *RevocationResult {
	ocspURL := getOCSPURL(cert)
	if ocspURL == "" {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  "OCSP URL не найден в расширении AIA",
		}
	}

	cacheKey := hex.EncodeToString(cert.SerialNumber.Bytes()) + ":" + ocspURL
	oc.cacheMu.RLock()
	if cached, ok := oc.cache[cacheKey]; ok {
		if time.Since(cached.fetchedAt) < time.Duration(oc.cacheTTL)*time.Second {
			oc.cacheMu.RUnlock()
			return cached.result
		}
	}
	oc.cacheMu.RUnlock()

	requestDER, err := oc.buildOCSPRequest(cert, issuer)
	if err != nil {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("не удалось создать OCSP запрос: %v", err),
		}
	}

	responseDER, err := oc.sendOCSPRequest(ocspURL, requestDER)
	if err != nil {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("OCSP запрос не удался: %v", err),
		}
	}

	result, err := oc.parseOCSPResponse(responseDER, cert, issuer)
	if err != nil {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("не удалось разобрать OCSP ответ: %v", err),
		}
	}

	if result.Status != StatusUnknown && oc.cacheTTL > 0 {
		oc.cacheMu.Lock()
		oc.cache[cacheKey] = &OCSPCacheEntry{
			result:       result,
			fetchedAt:    time.Now(),
			responderURL: ocspURL,
		}
		oc.cacheMu.Unlock()
	}

	return result
}

// Структуры ASN.1 для OCSP запроса согласно RFC 6960
type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   asn1.RawValue
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version       int
	RequestorName asn1.RawValue `asn1:"optional,explicit,tag:0"`
	RequestList   []request
}

type request struct {
	CertID asn1.RawValue
}

// buildOCSPRequest создает OCSP запрос согласно RFC 6960
func (oc *OCSPChecker) buildOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	hash := sha1.New()
	hash.Write(issuer.RawSubject)
	nameHash := hash.Sum(nil)

	hash.Reset()
	pubKeyDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать публичный ключ: %w", err)
	}
	hash.Write(pubKeyDER)
	keyHash := hash.Sum(nil)

	certID := ocspCertID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
		},
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   asn1.RawValue{Bytes: cert.SerialNumber.Bytes()},
	}

	certIDDER, err := asn1.Marshal(certID)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать CertID: %w", err)
	}

	req := ocspRequest{
		TBSRequest: tbsRequest{
			Version:     0,
			RequestList: []request{{CertID: asn1.RawValue{FullBytes: certIDDER}}},
		},
	}

	return asn1.Marshal(req)
}

// Структуры для парсинга OCSP ответа - синхронизированы с сервером
type ocspResponse struct {
	ResponseStatus int
	ResponseBytes  struct {
		ResponseType asn1.ObjectIdentifier
		Response     []byte
	} `asn1:"optional,explicit,tag:0"`
}

type basicOCSPResponse struct {
	TBSResponseData    []byte
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type tbsResponseData struct {
	Version            int
	ResponderID        asn1.RawValue
	ProducedAt         time.Time
	Responses          []singleResponse
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type singleResponse struct {
	CertID           asn1.RawValue
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time
	NextUpdate       time.Time        `asn1:"optional,explicit,tag:0"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

// sendOCSPRequest отправляет OCSP запрос
func (oc *OCSPChecker) sendOCSPRequest(url string, request []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	req.Header.Set("User-Agent", oc.userAgent)

	resp, err := oc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP статус %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// parseOCSPResponse парсит ответ OCSP
func (oc *OCSPChecker) parseOCSPResponse(resp []byte, cert, issuer *x509.Certificate) (*RevocationResult, error) {
	var ocspResp ocspResponse
	rest, err := asn1.Unmarshal(resp, &ocspResp)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить OCSP ответ: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("лишние данные после OCSP ответа")
	}

	if ocspResp.ResponseStatus != 0 {
		return &RevocationResult{
			Status: StatusUnknown,
			Error:  fmt.Sprintf("OCSP responder вернул статус %d", ocspResp.ResponseStatus),
		}, nil
	}

	var basic basicOCSPResponse
	_, err = asn1.Unmarshal(ocspResp.ResponseBytes.Response, &basic)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить BasicOCSPResponse: %w", err)
	}

	var tbs tbsResponseData
	_, err = asn1.Unmarshal(basic.TBSResponseData, &tbs)
	if err != nil {
		return nil, fmt.Errorf("не удалось распарсить TBSResponseData: %w", err)
	}

	for _, single := range tbs.Responses {
		var certID ocspCertID
		_, err := asn1.Unmarshal(single.CertID.FullBytes, &certID)
		if err != nil {
			continue
		}

		respSerial := new(big.Int).SetBytes(certID.SerialNumber.Bytes)
		if respSerial.Cmp(cert.SerialNumber) != 0 {
			continue
		}

		if single.CertStatus.Tag == asn1.TagNull {
			return &RevocationResult{
				Status: StatusGood,
			}, nil
		} else if single.CertStatus.Tag == 0 {
			var revInfo struct {
				RevocationTime time.Time
				Reason         int `asn1:"optional,explicit,tag:0"`
			}
			_, err := asn1.Unmarshal(single.CertStatus.Bytes, &revInfo)
			if err == nil {
				reason := mapOCSPReason(revInfo.Reason)
				return &RevocationResult{
					Status:           StatusRevoked,
					RevocationTime:   &revInfo.RevocationTime,
					RevocationReason: &reason,
				}, nil
			}
			return &RevocationResult{
				Status: StatusRevoked,
			}, nil
		} else {
			return &RevocationResult{
				Status: StatusUnknown,
			}, nil
		}
	}

	return &RevocationResult{
		Status: StatusUnknown,
		Error:  "сертификат не найден в ответе OCSP",
	}, nil
}

// mapOCSPReason преобразует код причины в строку
func mapOCSPReason(reason int) string {
	switch reason {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return "unknown"
	}
}

// ClearCache очищает кэш
func (oc *OCSPChecker) ClearCache() {
	oc.cacheMu.Lock()
	defer oc.cacheMu.Unlock()
	oc.cache = make(map[string]*OCSPCacheEntry)
}
