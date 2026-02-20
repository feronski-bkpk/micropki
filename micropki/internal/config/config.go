// Package config предоставляет функциональность для загрузки конфигурации
// из файлов YAML/JSON и переменных окружения.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config представляет полную конфигурацию MicroPKI.
type Config struct {
	Database DatabaseConfig `json:"database" yaml:"database"`
	Server   ServerConfig   `json:"server" yaml:"server"`
	PKI      PKIConfig      `json:"pki" yaml:"pki"`
	Logging  LoggingConfig  `json:"logging" yaml:"logging"`
}

// DatabaseConfig содержит настройки базы данных.
type DatabaseConfig struct {
	Path      string `json:"path" yaml:"path"`
	WALMode   bool   `json:"wal_mode" yaml:"wal_mode"`
	CacheSize int    `json:"cache_size" yaml:"cache_size"`
}

// ServerConfig содержит настройки HTTP сервера репозитория.
type ServerConfig struct {
	Host           string   `json:"host" yaml:"host"`
	Port           int      `json:"port" yaml:"port"`
	CertDir        string   `json:"cert_dir" yaml:"cert_dir"`
	EnableCORS     bool     `json:"enable_cors" yaml:"enable_cors"`
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins"`
}

// PKIConfig содержит настройки PKI по умолчанию.
type PKIConfig struct {
	DefaultKeyType   string `json:"default_key_type" yaml:"default_key_type"`
	DefaultKeySize   int    `json:"default_key_size" yaml:"default_key_size"`
	RootValidityDays int    `json:"root_validity_days" yaml:"root_validity_days"`
	IntValidityDays  int    `json:"int_validity_days" yaml:"int_validity_days"`
	CertValidityDays int    `json:"cert_validity_days" yaml:"cert_validity_days"`
	OutDir           string `json:"out_dir" yaml:"out_dir"`
}

// LoggingConfig содержит настройки логирования.
type LoggingConfig struct {
	Level      string `json:"level" yaml:"level"`
	File       string `json:"file" yaml:"file"`
	JSONFormat bool   `json:"json_format" yaml:"json_format"`
}

// DefaultConfig возвращает конфигурацию по умолчанию.
func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Path:      "./pki/micropki.db",
			WALMode:   true,
			CacheSize: 2000,
		},
		Server: ServerConfig{
			Host:           "127.0.0.1",
			Port:           8080,
			CertDir:        "./pki/certs",
			EnableCORS:     true,
			AllowedOrigins: []string{"*"},
		},
		PKI: PKIConfig{
			DefaultKeyType:   "rsa",
			DefaultKeySize:   4096,
			RootValidityDays: 3650,
			IntValidityDays:  1825,
			CertValidityDays: 365,
			OutDir:           "./pki",
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       "",
			JSONFormat: false,
		},
	}
}

// Load загружает конфигурацию из файла.
// Поддерживаются форматы: .yaml, .yml, .json
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл конфигурации: %w", err)
	}

	config := DefaultConfig()
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("не удалось разобрать YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("не удалось разобрать JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый формат файла: %s (поддерживаются .yaml, .yml, .json)", ext)
	}

	// Применяем переменные окружения (переопределяют файл)
	config.applyEnvOverrides()

	return config, nil
}

// Save сохраняет конфигурацию в файл.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("не удалось сериализовать конфигурацию: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("не удалось записать файл конфигурации: %w", err)
	}

	return nil
}

// applyEnvOverrides применяет переопределения из переменных окружения.
// Переменные имеют формат MICROPKI_<SECTION>_<KEY>.
func (c *Config) applyEnvOverrides() {
	// База данных
	if val := os.Getenv("MICROPKI_DATABASE_PATH"); val != "" {
		c.Database.Path = val
	}

	// Сервер
	if val := os.Getenv("MICROPKI_SERVER_HOST"); val != "" {
		c.Server.Host = val
	}
	if val := os.Getenv("MICROPKI_SERVER_PORT"); val != "" {
		fmt.Sscanf(val, "%d", &c.Server.Port)
	}
	if val := os.Getenv("MICROPKI_SERVER_CERT_DIR"); val != "" {
		c.Server.CertDir = val
	}

	// PKI
	if val := os.Getenv("MICROPKI_PKI_OUT_DIR"); val != "" {
		c.PKI.OutDir = val
	}

	// Логирование
	if val := os.Getenv("MICROPKI_LOGGING_LEVEL"); val != "" {
		c.Logging.Level = val
	}
	if val := os.Getenv("MICROPKI_LOGGING_FILE"); val != "" {
		c.Logging.File = val
	}
}

// ExampleConfig создает пример конфигурационного файла.
func ExampleConfig() string {
	return `# MicroPKI Configuration Example

database:
  # Путь к файлу базы данных SQLite
  path: "./pki/micropki.db"
  # Режим WAL для лучшей производительности
  wal_mode: true
  # Размер кэша страниц
  cache_size: 2000

server:
  # Адрес для прослушивания
  host: "127.0.0.1"
  # Порт
  port: 8080
  # Директория с сертификатами CA
  cert_dir: "./pki/certs"
  # Включить CORS заголовки
  enable_cors: true
  # Разрешенные источники (для CORS)
  allowed_origins:
    - "*"

pki:
  # Тип ключа по умолчанию (rsa или ecc)
  default_key_type: "rsa"
  # Размер ключа по умолчанию
  default_key_size: 4096
  # Срок действия корневого CA в днях
  root_validity_days: 3650
  # Срок действия промежуточного CA в днях
  int_validity_days: 1825
  # Срок действия конечных сертификатов в днях
  cert_validity_days: 365
  # Выходная директория для сертификатов
  out_dir: "./pki"

logging:
  # Уровень логирования (debug, info, warn, error)
  level: "info"
  # Файл для логов (пусто = stderr)
  file: ""
  # Использовать JSON формат
  json_format: false
`
}
