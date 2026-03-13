// Package repository реализует HTTP сервер для обслуживания сертификатов
// и точек распространения CRL.
package repository

import (
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

	"micropki/micropki/internal/database"
)

// Server представляет HTTP сервер репозитория сертификатов.
type Server struct {
	db       *database.DB
	certDir  string
	logger   *log.Logger
	httpServ *http.Server
	pkiDir   string
}

// Config содержит конфигурацию для сервера репозитория.
type Config struct {
	Host     string
	Port     int
	DBPath   string
	CertDir  string
	LogFile  string
	LogLevel string
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

	logger.Printf("Server initialized with:")
	logger.Printf("  DB Path: %s", cfg.DBPath)
	logger.Printf("  Cert Dir: %s", cfg.CertDir)
	logger.Printf("  PKI Dir: %s", pkiDir)
	logger.Printf("  Log File: %s", cfg.LogFile)

	return &Server{
		db:      db,
		certDir: cfg.CertDir,
		logger:  logger,
		pkiDir:  pkiDir,
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

// loggingMiddleware логирует все входящие HTTP запросы.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.logger.Printf("%s %s %d %s %s %v",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			r.RemoteAddr,
			r.UserAgent(),
			duration,
		)
	})
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
	s.logger.Printf("=== CRL HANDLER CALLED ===")
	s.logger.Printf("Method: %s", r.Method)
	s.logger.Printf("URL Path: %s", r.URL.Path)
	s.logger.Printf("URL RawQuery: %s", r.URL.RawQuery)
	s.logger.Printf("User-Agent: %s", r.UserAgent())
	s.logger.Printf("RemoteAddr: %s", r.RemoteAddr)

	if r.Method != http.MethodGet {
		s.logger.Printf("ERROR: Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Printf("GET request accepted")

	if r.URL.Path == "/crl" {
		s.logger.Printf("Handling /crl endpoint")

		caName := r.URL.Query().Get("ca")
		s.logger.Printf("ca parameter: '%s'", caName)

		if caName == "" {
			caName = "intermediate"
			s.logger.Printf("Using default ca: intermediate")
		}

		if caName != "root" && caName != "intermediate" {
			s.logger.Printf("Invalid ca value: %s", caName)
			http.Error(w, "CA must be 'root' or 'intermediate'", http.StatusBadRequest)
			return
		}

		crlPath := filepath.Join(s.pkiDir, "crl", caName+".crl.pem")
		s.logger.Printf("Looking for CRL at: %s", crlPath)

		s.serveCRLFile(w, crlPath, caName)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/crl/") {
		s.logger.Printf("Handling /crl/ endpoint")

		filename := strings.TrimPrefix(r.URL.Path, "/crl/")
		s.logger.Printf("Filename: %s", filename)

		filename = filepath.Base(filename)
		s.logger.Printf("Base filename: %s", filename)

		var caName string
		if filename == "root.crl" || filename == "root.crl.pem" {
			caName = "root"
		} else if filename == "intermediate.crl" || filename == "intermediate.crl.pem" {
			caName = "intermediate"
		} else {
			s.logger.Printf("Invalid filename: %s", filename)
			http.Error(w, "Invalid CRL filename", http.StatusBadRequest)
			return
		}

		s.logger.Printf("CA name: %s", caName)

		crlPath := filepath.Join(s.pkiDir, "crl", caName+".crl.pem")
		s.logger.Printf("Looking for CRL at: %s", crlPath)

		s.serveCRLFile(w, crlPath, caName)
		return
	}

	s.logger.Printf("Unknown path: %s", r.URL.Path)
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

	s.logger.Printf("CRL file found, size: %d bytes", fileInfo.Size())

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		s.logger.Printf("Error reading CRL file: %v", err)
		http.Error(w, "Error reading CRL file", http.StatusInternalServerError)
		return
	}

	s.logger.Printf("Successfully read CRL file, size: %d bytes", len(crlPEM))

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.crl.pem\"", caName))
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", fmt.Sprintf("\"%d-%d\"", fileInfo.Size(), fileInfo.ModTime().Unix()))
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")

	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
	s.logger.Printf("Successfully served CRL for %s", caName)
}

// handleCRLFile обрабатывает GET /crl/<filename>.crl для статических файлов
func (s *Server) handleCRLFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.logger.Printf("Method not allowed: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/crl/")
	if filename == "" {
		http.Error(w, "Имя файла CRL не указано", http.StatusBadRequest)
		return
	}

	s.logger.Printf("Handling CRL file request: %s", filename)

	if !strings.HasSuffix(filename, ".crl") && !strings.HasSuffix(filename, ".crl.pem") {
		s.logger.Printf("Invalid file extension: %s", filename)
		http.Error(w, "Неверный формат файла CRL", http.StatusBadRequest)
		return
	}

	filename = filepath.Base(filename)

	crlPath := filepath.Join(s.pkiDir, "crl", filename)
	s.logger.Printf("Looking for CRL file at: %s", crlPath)

	if _, err := os.Stat(crlPath); err != nil {
		s.logger.Printf("CRL file not found: %v", err)
		http.Error(w, "CRL файл не найден", http.StatusNotFound)
		return
	}

	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		s.logger.Printf("Error reading CRL file: %v", err)
		http.Error(w, "Ошибка чтения CRL файла", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	fileInfo, err := os.Stat(crlPath)
	if err == nil {
		w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
		etag := fmt.Sprintf("\"%d-%d\"", fileInfo.Size(), fileInfo.ModTime().Unix())
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	}

	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
	s.logger.Printf("Successfully served CRL file %s, size: %d bytes", filename, len(crlPEM))
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

	crlDir := filepath.Join(s.pkiDir, "crl")
	if _, err := os.Stat(crlDir); err != nil {
		s.logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Директория CRL не доступна: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","database":"connected"}`))
}

// tryServeFromFileSystem пытается найти сертификат в файловой системе
// для обратной совместимости.
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
