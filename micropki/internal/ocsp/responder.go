package ocsp

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Responder представляет OCSP-ответчик
type Responder struct {
	db            StatusChecker
	responderCert *x509.Certificate
	responderKey  crypto.PrivateKey
	issuerCert    *x509.Certificate
	cache         *ResponseCache
	cacheTTL      int
	logger        *log.Logger
	mu            sync.RWMutex
}

// ResponderConfig содержит конфигурацию для OCSP-ответчика
type ResponderConfig struct {
	DB            StatusChecker
	ResponderCert *x509.Certificate
	ResponderKey  crypto.Signer
	IssuerCert    *x509.Certificate
	CacheTTL      int
	Logger        *log.Logger
	EnableCache   bool
}

// NewResponder создаёт новый OCSP-ответчик
func NewResponder(config *ResponderConfig) *Responder {
	r := &Responder{
		db:            config.DB,
		responderCert: config.ResponderCert,
		responderKey:  config.ResponderKey,
		issuerCert:    config.IssuerCert,
		cacheTTL:      config.CacheTTL,
		logger:        config.Logger,
	}

	if config.EnableCache {
		r.cache = NewResponseCache(config.CacheTTL)
	}

	return r
}

// ServeHTTP реализует http.Handler для OCSP-запросов
func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	clientIP := r.getClientIP(req)

	if req.Method != http.MethodPost {
		r.logger.Printf("WARN: %s - метод %s не поддерживается", clientIP, req.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Content-Type") != "application/ocsp-request" {
		r.logger.Printf("WARN: %s - неверный Content-Type: %s", clientIP, req.Header.Get("Content-Type"))
		http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		r.logger.Printf("ERROR: %s - не удалось прочитать тело запроса: %v", clientIP, err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	responseDER, err := r.handleRequest(body, clientIP)

	duration := time.Since(startTime)
	r.logRequest(clientIP, body, responseDER, err, duration)

	if err != nil {
		if ocspErr, ok := err.(*OCSPError); ok {
			errorDER, _ := r.buildErrorResponse(ocspErr.Status)
			w.Header().Set("Content-Type", "application/ocsp-response")
			w.WriteHeader(http.StatusOK)
			w.Write(errorDER)
		} else {
			r.logger.Printf("ERROR: %s - внутренняя ошибка: %v", clientIP, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", r.cacheTTL))
	w.WriteHeader(http.StatusOK)
	w.Write(responseDER)
}

// handleRequest обрабатывает OCSP-запрос
func (r *Responder) handleRequest(requestDER []byte, clientIP string) ([]byte, error) {
	req, err := ParseRequest(requestDER)
	if err != nil {
		return nil, err
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	var serialHex string
	var statusResult *StatusResult

	if len(req.RequestList) > 0 {
		serial := req.RequestList[0].CertID.SerialNumber
		serialHex = hex.EncodeToString(serial.Bytes())

		statusResult, err = r.db.GetCertificateStatus(serialHex)
		if err != nil {
			r.logger.Printf("ERROR: Failed to get status from DB for %s: %v", serialHex, err)
		} else {
			r.logger.Printf("Certificate %s status from DB: %s", serialHex, statusResult.Status.String())
		}
	}

	config := &ResponseConfig{
		Request:           req,
		IssuerCert:        r.issuerCert,
		ResponderCert:     r.responderCert,
		ResponderKey:      r.responderKey,
		DB:                r.db,
		CacheTTL:          r.cacheTTL,
		ProducedAt:        time.Now().UTC(),
		IncludeNextUpdate: true,
	}

	builder := NewResponseBuilder(config)
	responseDER, err := builder.Build()
	if err != nil {
		return nil, err
	}

	if r.cache != nil && statusResult != nil && statusResult.Status == StatusRevoked {
		r.cache.InvalidateBySerial(serialHex)
		r.logger.Printf("Cache invalidated for revoked certificate %s", serialHex)
	}

	return responseDER, nil
}

// buildErrorResponse строит ответ с ошибкой
func (r *Responder) buildErrorResponse(status OCSPResponseStatus) ([]byte, error) {
	type errorResponse struct {
		Status int
	}

	resp := errorResponse{
		Status: int(status),
	}
	return asn1.Marshal(resp)
}

// getClientIP извлекает IP клиента из запроса
func (r *Responder) getClientIP(req *http.Request) string {
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	ip := req.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// logRequest логирует OCSP-запрос
func (r *Responder) logRequest(clientIP string, requestDER []byte, responseDER []byte, err error, duration time.Duration) {
	if r.logger == nil {
		return
	}
	var serials []string
	var nonceStr string

	req, parseErr := ParseRequest(requestDER)
	if parseErr == nil {
		for _, entry := range req.RequestList {
			serials = append(serials, fmt.Sprintf("%X", entry.CertID.SerialNumber))
		}
		nonce, _ := req.GetNonce()
		if nonce != nil {
			nonceStr = hex.EncodeToString(nonce)
		}
	}

	status := "unknown"
	if err != nil {
		if ocspErr, ok := err.(*OCSPError); ok {
			status = ocspErr.Status.String()
		} else {
			status = "internal_error"
		}
	} else {
		status = "successful"
	}

	r.logger.Printf("INFO: client=%s method=OCSP status=%s serials=%v nonce=%s duration=%v",
		clientIP, status, serials, nonceStr, duration)
}
