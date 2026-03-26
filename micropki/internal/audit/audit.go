package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel представляет уровень серьезности записи аудита
type LogLevel string

const (
	LevelAudit LogLevel = "AUDIT"
	LevelInfo  LogLevel = "INFO"
	LevelError LogLevel = "ERROR"
	LevelWarn  LogLevel = "WARN"
)

// LogEntry представляет одну запись в журнале аудита
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Operation string                 `json:"operation"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata"`
	Integrity IntegrityInfo          `json:"integrity"`
}

// IntegrityInfo содержит информацию о целостности записи
type IntegrityInfo struct {
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// AuditLogger - основной логгер аудита
type AuditLogger struct {
	logPath     string
	chainPath   string
	file        *os.File
	writer      *bufio.Writer
	mu          sync.Mutex
	lastHash    string
	logger      *log.Logger
	initialized bool
	maxSize     int64
	maxBackups  int
}

// NewAuditLogger создает новый экземпляр логгера аудита (без ротации)
func NewAuditLogger(logPath, chainPath string, logger *log.Logger) (*AuditLogger, error) {
	return NewAuditLoggerWithRotation(logPath, chainPath, 0, 0, logger)
}

// NewAuditLoggerWithRotation создает логгер с ротацией
func NewAuditLoggerWithRotation(logPath, chainPath string, maxSizeMB, maxBackups int, logger *log.Logger) (*AuditLogger, error) {
	auditDir := filepath.Dir(logPath)
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return nil, fmt.Errorf("не удалось создать директорию для аудита: %w", err)
	}

	al := &AuditLogger{
		logPath:    logPath,
		chainPath:  chainPath,
		logger:     logger,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}

	if err := al.init(); err != nil {
		return nil, err
	}

	return al, nil
}

// init инициализирует логгер аудита
func (al *AuditLogger) init() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	var err error
	al.file, err = os.OpenFile(al.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("не удалось открыть файл аудита: %w", err)
	}
	al.writer = bufio.NewWriter(al.file)

	chainData, err := os.ReadFile(al.chainPath)
	if err == nil && len(chainData) > 0 {
		al.lastHash = string(chainData)
	} else {
		al.lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	al.initialized = true
	return nil
}

// rotateLog выполняет ротацию лога при необходимости
func (al *AuditLogger) rotateLog() error {
	if al.maxSize <= 0 {
		return nil
	}

	info, err := os.Stat(al.logPath)
	if err != nil {
		return err
	}

	if info.Size() < al.maxSize {
		return nil
	}

	if al.writer != nil {
		al.writer.Flush()
	}
	if al.file != nil {
		al.file.Close()
	}

	for i := al.maxBackups; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", al.logPath, i)
		newPath := fmt.Sprintf("%s.%d", al.logPath, i+1)

		if i == al.maxBackups {
			os.Remove(oldPath)
		} else {
			os.Rename(oldPath, newPath)
		}
	}

	os.Rename(al.logPath, al.logPath+".1")

	file, err := os.OpenFile(al.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("не удалось создать новый файл аудита: %w", err)
	}

	al.file = file
	al.writer = bufio.NewWriter(file)

	if al.logger != nil {
		al.logger.Printf("INFO: Выполнена ротация журнала аудита (размер: %d MB)", info.Size()/1024/1024)
	}

	return nil
}

// Log создает новую запись аудита
func (al *AuditLogger) Log(level LogLevel, operation, status, message string, metadata map[string]interface{}) error {
	if !al.initialized {
		return fmt.Errorf("аудиторный логгер не инициализирован")
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	if al.maxSize > 0 {
		if err := al.rotateLog(); err != nil {
			if al.logger != nil {
				al.logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Ошибка ротации журнала: %v", err)
			}
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Operation: operation,
		Status:    status,
		Message:   message,
		Metadata:  metadata,
		Integrity: IntegrityInfo{
			PrevHash: al.lastHash,
		},
	}

	hashInput, err := al.canonicalJSONWithoutHash(entry)
	if err != nil {
		return fmt.Errorf("не удалось создать канонический JSON: %w", err)
	}

	hash := sha256.Sum256(hashInput)
	entry.Integrity.Hash = hex.EncodeToString(hash[:])

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("не удалось сериализовать запись: %w", err)
	}

	if _, err := al.writer.Write(jsonData); err != nil {
		return fmt.Errorf("не удалось записать в журнал: %w", err)
	}
	if _, err := al.writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("не удалось записать разделитель: %w", err)
	}

	if err := al.writer.Flush(); err != nil {
		return fmt.Errorf("не удалось сбросить буфер: %w", err)
	}

	al.lastHash = entry.Integrity.Hash

	if err := os.WriteFile(al.chainPath, []byte(al.lastHash), 0644); err != nil {
		if al.logger != nil {
			al.logger.Printf("ПРЕДУПРЕЖДЕНИЕ: Не удалось сохранить файл цепочки: %v", err)
		}
	}

	if al.logger != nil {
		al.logger.Printf("AUDIT: %s - %s - %s", operation, status, message)
	}

	return nil
}

// canonicalJSONWithoutHash создает канонический JSON без поля hash
func (al *AuditLogger) canonicalJSONWithoutHash(entry LogEntry) ([]byte, error) {
	tempEntry := entry
	tempEntry.Integrity.Hash = ""

	return json.Marshal(tempEntry)
}

// Close закрывает логгер
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.writer != nil {
		al.writer.Flush()
	}
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// GetLastHash возвращает последний хеш цепочки
func (al *AuditLogger) GetLastHash() string {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.lastHash
}
