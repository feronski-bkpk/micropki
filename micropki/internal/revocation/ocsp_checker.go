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

// OCSPRequest представляет OCSP запрос (упрощённо)
type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version           int
	RequestorName     asn1.RawValue `asn1:"optional,explicit,tag:0"`
	RequestList       []request
	RequestExtensions []pkix.Extension `asn1:"optional,explicit,tag:2"`
}

type request struct {
	CertID                  certID
	SingleRequestExtensions []pkix.Extension `asn1:"optional,explicit,tag:0"`
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	SerialNumber  asn1.RawValue
}

// OCSPResponse представляет ответ OCSP
type ocspResponse struct {
	ResponseStatus int
	ResponseBytes  responseBytes `asn1:"optional,explicit,tag:0"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// basicOCSPResponse представляет базовый ответ OCSP
type basicOCSPResponse struct {
	TBSResponseData    tbsResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"optional"`
}

type tbsResponseData struct {
	Version            int
	ResponderID        asn1.RawValue
	ProducedAt         time.Time
	Responses          []singleResponse
	ResponseExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
}

type singleResponse struct {
	CertID           certID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time
	NextUpdate       time.Time        `asn1:"optional"`
	SingleExtensions []pkix.Extension `asn1:"optional,explicit,tag:1"`
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

// buildOCSPRequest создает OCSP запрос
func (oc *OCSPChecker) buildOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	hash := sha1.New()
	hash.Write(issuer.RawSubject)
	nameHash := hash.Sum(nil)

	hash.Reset()
	pubKeyDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	hash.Write(pubKeyDER)
	keyHash := hash.Sum(nil)

	certID := certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
		},
		NameHash:     nameHash,
		KeyHash:      keyHash,
		SerialNumber: asn1.RawValue{Bytes: cert.SerialNumber.Bytes()},
	}

	req := ocspRequest{
		TBSRequest: tbsRequest{
			Version: 0,
			RequestList: []request{
				{
					CertID: certID,
				},
			},
		},
	}

	return asn1.Marshal(req)
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
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("лишние данные после ответа")
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
		return nil, err
	}

	for _, single := range basic.TBSResponseData.Responses {
		var serialNum int
		_, err := asn1.Unmarshal(single.CertID.SerialNumber.FullBytes, &serialNum)
		if err != nil {
			continue
		}

		if single.CertStatus.Bytes == nil {
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
