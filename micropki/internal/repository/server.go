// Package repository реализует HTTP сервер для обслуживания сертификатов
// и точек распространения CRL.
package repository

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
	// Подключаемся к базе данных
	db, err := database.New(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к БД: %w", err)
	}

	// Настраиваем логгер
	var logger *log.Logger
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть файл лога: %w", err)
		}
		logger = log.New(logFile, "[HTTP] ", log.LstdFlags)
	} else {
		logger = log.New(os.Stdout, "[HTTP] ", log.LstdFlags)
	}

	// Убеждаемся, что директория с сертификатами существует
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("не удалось создать директорию сертификатов: %w", err)
	}

	return &Server{
		db:      db,
		certDir: cfg.CertDir,
		logger:  logger,
	}, nil
}

// Start запускает HTTP сервер на указанном хосте и порту.
func (s *Server) Start(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Создаем мультиплексор маршрутов
	mux := http.NewServeMux()

	// Регистрируем обработчики
	mux.HandleFunc("/certificate/", s.handleCertificate)
	mux.HandleFunc("/ca/", s.handleCA)
	mux.HandleFunc("/crl", s.handleCRL)
	mux.HandleFunc("/health", s.handleHealth)

	// Добавляем middleware для логирования
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

		// Создаем обертку для ResponseWriter чтобы перехватить статус код
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Обрабатываем запрос
		next.ServeHTTP(rw, r)

		// Логируем запрос
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

	// Извлекаем серийный номер из URL
	path := strings.TrimPrefix(r.URL.Path, "/certificate/")
	if path == "" {
		http.Error(w, "Серийный номер не указан", http.StatusBadRequest)
		return
	}

	// Проверяем формат серийного номера (должен быть hex)
	serialHex := strings.ToLower(path)
	if _, err := hex.DecodeString(serialHex); err != nil {
		http.Error(w, "Неверный формат серийного номера (ожидается hex)", http.StatusBadRequest)
		return
	}

	// Ищем сертификат в БД
	record, err := s.db.GetCertificateBySerial(serialHex)
	if err != nil {
		// Если не нашли, пробуем найти в файловой системе (fallback)
		if s.tryServeFromFileSystem(w, serialHex) {
			return
		}
		http.Error(w, "Сертификат не найден", http.StatusNotFound)
		return
	}

	// Проверяем статус (для Sprint 3 возвращаем даже отозванные)
	if record.Status == "revoked" {
		s.logger.Printf("Предупреждение: запрошен отозванный сертификат %s", serialHex)
		// Можем вернуть 410 Gone, но в Sprint 3 возвращаем сертификат
	}

	// Отправляем PEM сертификат
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

	// Извлекаем уровень CA из URL
	level := strings.TrimPrefix(r.URL.Path, "/ca/")
	if level == "" {
		http.Error(w, "Уровень CA не указан", http.StatusBadRequest)
		return
	}

	// Проверяем допустимые значения
	if level != "root" && level != "intermediate" {
		http.Error(w, "Уровень CA должен быть 'root' или 'intermediate'", http.StatusBadRequest)
		return
	}

	// Формируем путь к файлу сертификата
	var certPath string
	if level == "root" {
		certPath = filepath.Join(s.certDir, "..", "root", "certs", "ca.cert.pem")
	} else {
		certPath = filepath.Join(s.certDir, "..", "intermediate", "certs", "intermediate.cert.pem")
	}

	// Пытаемся прочитать файл
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		// Пробуем альтернативный путь (если сертификаты прямо в certDir)
		certPath = filepath.Join(s.certDir, level+".cert.pem")
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			http.Error(w, "Сертификат CA не найден", http.StatusNotFound)
			return
		}
	}

	// Отправляем PEM сертификат
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-ca.pem\"", level))
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

// handleCRL обрабатывает GET /crl (заглушка для Sprint 4)
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Заглушка для Sprint 3
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("CRL generation not yet implemented (Sprint 4)"))
}

// handleHealth обрабатывает GET /health для проверки работоспособности
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем подключение к БД
	if err := s.db.Ping(); err != nil {
		http.Error(w, "База данных недоступна", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","database":"connected"}`))
}

// tryServeFromFileSystem пытается найти сертификат в файловой системе
// для обратной совместимости.
func (s *Server) tryServeFromFileSystem(w http.ResponseWriter, serialHex string) bool {
	// Пробуем найти в стандартных местах
	possiblePaths := []string{
		filepath.Join(s.certDir, serialHex+".pem"),
		filepath.Join(s.certDir, serialHex+".cert.pem"),
		filepath.Join(filepath.Dir(s.certDir), "certs", serialHex+".pem"),
		filepath.Join(filepath.Dir(s.certDir), "certs", serialHex+".cert.pem"),
	}

	for _, path := range possiblePaths {
		if certPEM, err := os.ReadFile(path); err == nil {
			// Проверяем, что это действительно PEM сертификат
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
