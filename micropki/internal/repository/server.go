// Package repository реализует HTTP сервер для обслуживания сертификатов
// и точек распространения CRL.
package repository

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/micropki/internal/ca"
	"micropki/micropki/internal/database"
	"micropki/micropki/internal/ratelimit"
	"micropki/micropki/internal/templates"
)

// Server представляет HTTP сервер репозитория сертификатов.
type Server struct {
	db          *database.DB
	certDir     string
	logger      *log.Logger
	httpServ    *http.Server
	pkiDir      string
	rateLimiter *ratelimit.Limiter
}

// Config содержит конфигурацию для сервера репозитория.
type Config struct {
	Host      string
	Port      int
	DBPath    string
	CertDir   string
	LogFile   string
	LogLevel  string
	RateLimit float64
	RateBurst int
}

// NewServer создает новый экземпляр сервера репозитория.
func NewServer(cfg *Config) (*Server, error) {
	db, err := database.New(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
	}

	var logger *log.Logger
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть файл лога: %w", err)
		}
		multiWriter := io.MultiWriter(logFile, os.Stdout)
		logger = log.New(multiWriter, "[HTTP] ", log.LstdFlags)
	} else {
		logger = log.New(os.Stdout, "[HTTP] ", log.LstdFlags)
	}

	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("не удалось создать директорию сертификатов: %w", err)
	}

	pkiDir := filepath.Dir(filepath.Dir(cfg.CertDir))
	if !strings.HasSuffix(pkiDir, "pki") {
		pkiDir = filepath.Dir(cfg.CertDir)
	}

	var limiter *ratelimit.Limiter
	if cfg.RateLimit > 0 {
		limiter = ratelimit.NewLimiter(cfg.RateLimit, cfg.RateBurst)
		logger.Printf("Rate limiting enabled: %.2f req/s, burst: %d", cfg.RateLimit, cfg.RateBurst)
	}

	logger.Printf("Server initialized with:")
	logger.Printf("  DB Path: %s", cfg.DBPath)
	logger.Printf("  Cert Dir: %s", cfg.CertDir)
	logger.Printf("  PKI Dir: %s", pkiDir)
	logger.Printf("  Log File: %s", cfg.LogFile)

	return &Server{
		db:          db,
		certDir:     cfg.CertDir,
		logger:      logger,
		pkiDir:      pkiDir,
		rateLimiter: limiter,
	}, nil
}

// Start запускает HTTP сервер на указанном хосте и порту.
func (s *Server) Start(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/certificate/", s.handleCertificate)
	mux.HandleFunc("/ca/", s.handleCA)
	mux.HandleFunc("/crl", s.handleCRL)
	mux.HandleFunc("/crl/", s.handleCRL)
	mux.HandleFunc("/request-cert", s.handleRequestCert)

	handler := s.loggingMiddleware(mux)

	s.httpServ = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	s.logger.Printf("Запуск сервера на %s", addr)
	s.logger.Printf("База данных: %s", s.db.Path())
	s.logger.Printf("Директория сертификатов CA: %s", s.certDir)
	s.logger.Printf("Директория PKI: %s", s.pkiDir)

	if err := s.httpServ.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("ошибка сервера: %w", err)
	}

	return nil
}

// Stop останавливает HTTP сервер.
func (s *Server) Stop() error {
	if s.httpServ != nil {
		s.logger.Printf("Остановка сервера...")
		if err := s.db.Close(); err != nil {
			s.logger.Printf("Ошибка при закрытии БД: %v", err)
		}
		return s.httpServ.Close()
	}
	return nil
}

// getClientIP извлекает IP клиента из запроса
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// loggingMiddleware логирует все входящие HTTP запросы и применяет rate limiting.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		clientIP := getClientIP(r)

		if s.rateLimiter != nil {
			if !s.rateLimiter.Allow(clientIP) {
				w.Header().Set("Retry-After", "10")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				s.logger.Printf("Rate limit exceeded for %s on %s %s",
					clientIP, r.Method, r.URL.Path)
				return
			}
		}

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.logger.Printf("%s %s %d %s %s %v",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			clientIP,
			r.UserAgent(),
			duration,
		)
	})
}

// handleRequestCert обрабатывает POST /request-cert
func (s *Server) handleRequestCert(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientIP := getClientIP(r)

	s.logger.Printf("API REQUEST: POST /request-cert from %s, template=%s",
		clientIP, r.URL.Query().Get("template"))

	if r.Method != http.MethodPost {
		s.logger.Printf("API ERROR: Method not allowed from %s: %s", clientIP, r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		s.logger.Printf("API WARN: Request without API key from %s", clientIP)
	} else {
		s.logger.Printf("API INFO: Request with API key from %s", clientIP)
	}

	csrPEM, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("API ERROR: Failed to read request body from %s: %v", clientIP, err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if len(csrPEM) == 0 {
		s.logger.Printf("API ERROR: Empty request body from %s", clientIP)
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		s.logger.Printf("API ERROR: Invalid CSR format from %s", clientIP)
		http.Error(w, "Invalid CSR format", http.StatusBadRequest)
		return
	}

	template := r.URL.Query().Get("template")
	if template == "" {
		s.logger.Printf("API ERROR: Missing template parameter from %s", clientIP)
		http.Error(w, "Missing template parameter", http.StatusBadRequest)
		return
	}

	var tmplType templates.TemplateType
	switch template {
	case "server":
		tmplType = templates.Server
	case "client":
		tmplType = templates.Client
	case "code_signing":
		tmplType = templates.CodeSigning
	default:
		s.logger.Printf("API ERROR: Invalid template '%s' from %s", template, clientIP)
		http.Error(w, "Invalid template. Must be server, client, or code_signing", http.StatusBadRequest)
		return
	}

	s.logger.Printf("API INFO: Processing CSR request for template: %s from %s", template, clientIP)

	caCertPath := filepath.Join(s.pkiDir, "certs", "intermediate.cert.pem")
	caKeyPath := filepath.Join(s.pkiDir, "private", "intermediate.key.pem")
	passFile := filepath.Join(s.pkiDir, "int-pass.txt")

	if _, err := os.Stat(caCertPath); err != nil {
		s.logger.Printf("API ERROR: CA certificate not found: %v", err)
		http.Error(w, "CA certificate not found", http.StatusInternalServerError)
		return
	}
	if _, err := os.Stat(caKeyPath); err != nil {
		s.logger.Printf("API ERROR: CA key not found: %v", err)
		http.Error(w, "CA key not found", http.StatusInternalServerError)
		return
	}

	passphrase, err := os.ReadFile(passFile)
	if err != nil {
		s.logger.Printf("API ERROR: Failed to read passphrase file: %v", err)
		http.Error(w, "Failed to read CA passphrase", http.StatusInternalServerError)
		return
	}
	passphrase = bytes.TrimRight(passphrase, "\r\n")

	tempDir := filepath.Join(s.pkiDir, "temp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		s.logger.Printf("API ERROR: Failed to create temp dir: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	cert, err := ca.IssueCertificateFromCSR(
		caCertPath,
		caKeyPath,
		passphrase,
		csrPEM,
		tmplType,
		365,
		tempDir,
		s.db.Path(),
		s.logger,
	)

	if err != nil {
		s.logger.Printf("API ERROR: Failed to issue certificate: %v", err)
		http.Error(w, fmt.Sprintf("Failed to issue certificate: %v", err), http.StatusInternalServerError)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	duration := time.Since(startTime)
	s.logger.Printf("API SUCCESS: Certificate issued successfully for serial: %X from %s, duration: %v",
		cert.SerialNumber, clientIP, duration)

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-Serial-Number", hex.EncodeToString(cert.SerialNumber.Bytes()))
	w.WriteHeader(http.StatusCreated)
	w.Write(certPEM)
}

// handleCertificate обрабатывает GET /certificate/<serial>
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/certificate/")
	if path == "" {
		http.Error(w, "Серийный номер не указан", http.StatusBadRequest)
		return
	}

	serialHex := strings.ToLower(path)
	if _, err := hex.DecodeString(serialHex); err != nil {
		http.Error(w, "Неверный формат серийного номера (ожидается hex)", http.StatusBadRequest)
		return
	}

	record, err := s.db.GetCertificateBySerial(serialHex)
	if err != nil {
		if s.tryServeFromFileSystem(w, serialHex) {
			return
		}
		http.Error(w, "Сертификат не найден", http.StatusNotFound)
		return
	}

	if record.Status == "revoked" {
		s.logger.Printf("Предупреждение: запрошен отозванный сертификат %s", serialHex)
		w.Header().Set("X-Certificate-Status", "revoked")
		if record.RevocationReason.Valid {
			w.Header().Set("X-Revocation-Reason", record.RevocationReason.String)
		}
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.pem\"", serialHex))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(record.CertPEM))
}

// handleCA обрабатывает GET /ca/<level>
func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	level := strings.TrimPrefix(r.URL.Path, "/ca/")
	if level == "" {
		http.Error(w, "Уровень CA не указан", http.StatusBadRequest)
		return
	}

	if level != "root" && level != "intermediate" {
		http.Error(w, "Уровень CA должен быть 'root' или 'intermediate'", http.StatusBadRequest)
		return
	}

	var certPath string
	if level == "root" {
		certPath = filepath.Join(s.pkiDir, "root", "certs", "ca.cert.pem")
	} else {
		certPath = filepath.Join(s.pkiDir, "intermediate", "certs", "intermediate.cert.pem")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		certPath = filepath.Join(s.certDir, level+".cert.pem")
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			http.Error(w, "Сертификат CA не найден", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-ca.pem\"", level))
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

// handleCRL обрабатывает все GET запросы к CRL эндпоинтам
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.logger.Printf("ERROR: Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path == "/crl" {
		caName := r.URL.Query().Get("ca")
		if caName == "" {
			caName = "intermediate"
		}

		if caName != "root" && caName != "intermediate" {
			http.Error(w, "CA must be 'root' or 'intermediate'", http.StatusBadRequest)
			return
		}

		crlPath := filepath.Join(s.pkiDir, "crl", caName+".crl.pem")
		s.serveCRLFile(w, crlPath, caName)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/crl/") {
		filename := strings.TrimPrefix(r.URL.Path, "/crl/")
		filename = filepath.Base(filename)

		var caName string
		if filename == "root.crl" || filename == "root.crl.pem" {
			caName = "root"
		} else if filename == "intermediate.crl" || filename == "intermediate.crl.pem" {
			caName = "intermediate"
		} else {
			http.Error(w, "Invalid CRL filename", http.StatusBadRequest)
			return
		}

		crlPath := filepath.Join(s.pkiDir, "crl", caName+".crl.pem")
		s.serveCRLFile(w, crlPath, caName)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// serveCRLFile отдаёт CRL файл
func (s *Server) serveCRLFile(w http.ResponseWriter, crlPath string, caName string) {
	fileInfo, err := os.Stat(crlPath)
	if err != nil {
		s.logger.Printf("CRL file not found: %v", err)
		http.Error(w, fmt.Sprintf("CRL for CA '%s' not found", caName), http.StatusNotFound)
		return
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		s.logger.Printf("Error reading CRL file: %v", err)
		http.Error(w, "Error reading CRL file", http.StatusInternalServerError)
		return
	}

	etag := fmt.Sprintf("\"%d-%d\"", fileInfo.Size(), fileInfo.ModTime().Unix())

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.crl.pem\"", caName))
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")

	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
	s.logger.Printf("Successfully served CRL for %s, ETag: %s", caName, etag)
}

// handleHealth обрабатывает GET /health для проверки работоспособности
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	if err := s.db.Ping(); err != nil {
		http.Error(w, "База данных недоступна", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","database":"connected"}`))
}

// tryServeFromFileSystem пытается найти сертификат в файловой системе
func (s *Server) tryServeFromFileSystem(w http.ResponseWriter, serialHex string) bool {
	possiblePaths := []string{
		filepath.Join(s.certDir, serialHex+".pem"),
		filepath.Join(s.certDir, serialHex+".cert.pem"),
		filepath.Join(filepath.Dir(s.certDir), "certs", serialHex+".pem"),
		filepath.Join(filepath.Dir(s.certDir), "certs", serialHex+".cert.pem"),
	}

	for _, path := range possiblePaths {
		if certPEM, err := os.ReadFile(path); err == nil {
			block, _ := pem.Decode(certPEM)
			if block != nil && block.Type == "CERTIFICATE" {
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.Header().Set("X-Served-From", "filesystem")
				w.WriteHeader(http.StatusOK)
				w.Write(certPEM)
				return true
			}
		}
	}
	return false
}

// responseWriter обертка для http.ResponseWriter, которая запоминает статус код.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader перехватывает вызов WriteHeader для сохранения статус кода.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
