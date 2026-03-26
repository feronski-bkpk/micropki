package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DatabaseConfig содержит настройки базы данных
type DatabaseConfig struct {
	Path      string `json:"path" yaml:"path"`
	WALMode   bool   `json:"wal_mode" yaml:"wal_mode"`
	CacheSize int    `json:"cache_size" yaml:"cache_size"`
}

// ServerConfig содержит настройки HTTP сервера репозитория
type ServerConfig struct {
	Host           string   `json:"host" yaml:"host"`
	Port           int      `json:"port" yaml:"port"`
	CertDir        string   `json:"cert_dir" yaml:"cert_dir"`
	EnableCORS     bool     `json:"enable_cors" yaml:"enable_cors"`
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins"`
	RateLimit      float64  `json:"rate_limit" yaml:"rate_limit"`
	RateBurst      int      `json:"rate_burst" yaml:"rate_burst"`
}

// PKIConfig содержит настройки PKI по умолчанию
type PKIConfig struct {
	DefaultKeyType   string `json:"default_key_type" yaml:"default_key_type"`
	DefaultKeySize   int    `json:"default_key_size" yaml:"default_key_size"`
	RootValidityDays int    `json:"root_validity_days" yaml:"root_validity_days"`
	IntValidityDays  int    `json:"int_validity_days" yaml:"int_validity_days"`
	CertValidityDays int    `json:"cert_validity_days" yaml:"cert_validity_days"`
	OutDir           string `json:"out_dir" yaml:"out_dir"`
}

// LoggingConfig содержит настройки логирования
type LoggingConfig struct {
	Level      string `json:"level" yaml:"level"`
	File       string `json:"file" yaml:"file"`
	JSONFormat bool   `json:"json_format" yaml:"json_format"`
}

// PolicyConfig содержит настройки политик безопасности
type PolicyConfig struct {
	// RSA минимальные размеры ключей
	MinRSAKeySizeRootCA         int `json:"min_rsa_key_size_root_ca" yaml:"min_rsa_key_size_root_ca"`
	MinRSAKeySizeIntermediateCA int `json:"min_rsa_key_size_intermediate_ca" yaml:"min_rsa_key_size_intermediate_ca"`
	MinRSAKeySizeEndEntity      int `json:"min_rsa_key_size_end_entity" yaml:"min_rsa_key_size_end_entity"`

	// ECC минимальные размеры ключей
	MinECCKeySizeRootCA         int `json:"min_ecc_key_size_root_ca" yaml:"min_ecc_key_size_root_ca"`
	MinECCKeySizeIntermediateCA int `json:"min_ecc_key_size_intermediate_ca" yaml:"min_ecc_key_size_intermediate_ca"`
	MinECCKeySizeEndEntity      int `json:"min_ecc_key_size_end_entity" yaml:"min_ecc_key_size_end_entity"`

	// Максимальные сроки действия (в днях)
	MaxRootValidityDays         int `json:"max_root_validity_days" yaml:"max_root_validity_days"`
	MaxIntermediateValidityDays int `json:"max_intermediate_validity_days" yaml:"max_intermediate_validity_days"`
	MaxEndEntityValidityDays    int `json:"max_end_entity_validity_days" yaml:"max_end_entity_validity_days"`

	// Настройки SAN
	RejectWildcards               bool     `json:"reject_wildcards" yaml:"reject_wildcards"`
	AllowedSANTypesForServer      []string `json:"allowed_san_types_for_server" yaml:"allowed_san_types_for_server"`
	AllowedSANTypesForClient      []string `json:"allowed_san_types_for_client" yaml:"allowed_san_types_for_client"`
	AllowedSANTypesForCodeSigning []string `json:"allowed_san_types_for_code_signing" yaml:"allowed_san_types_for_code_signing"`
}

// AuditConfig содержит настройки аудита
type AuditConfig struct {
	LogPath        string `json:"log_path" yaml:"log_path"`
	ChainPath      string `json:"chain_path" yaml:"chain_path"`
	MaxSizeMB      int    `json:"max_size_mb" yaml:"max_size_mb"`
	MaxBackups     int    `json:"max_backups" yaml:"max_backups"`
	EnableRotation bool   `json:"enable_rotation" yaml:"enable_rotation"`
}

// Config содержит полную конфигурацию MicroPKI
type Config struct {
	Database DatabaseConfig `json:"database" yaml:"database"`
	Server   ServerConfig   `json:"server" yaml:"server"`
	PKI      PKIConfig      `json:"pki" yaml:"pki"`
	Logging  LoggingConfig  `json:"logging" yaml:"logging"`
	Policy   PolicyConfig   `json:"policy" yaml:"policy"`
	Audit    AuditConfig    `json:"audit" yaml:"audit"`
}

// DefaultPolicyConfig возвращает конфигурацию политик по умолчанию
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MinRSAKeySizeRootCA:           4096,
		MinRSAKeySizeIntermediateCA:   3072,
		MinRSAKeySizeEndEntity:        2048,
		MinECCKeySizeRootCA:           384,
		MinECCKeySizeIntermediateCA:   384,
		MinECCKeySizeEndEntity:        256,
		MaxRootValidityDays:           3650,
		MaxIntermediateValidityDays:   1825,
		MaxEndEntityValidityDays:      365,
		RejectWildcards:               true,
		AllowedSANTypesForServer:      []string{"dns", "ip"},
		AllowedSANTypesForClient:      []string{"dns", "email"},
		AllowedSANTypesForCodeSigning: []string{"dns", "uri"},
	}
}

// DefaultAuditConfig возвращает конфигурацию аудита по умолчанию
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		LogPath:        "./pki/audit/audit.log",
		ChainPath:      "./pki/audit/chain.dat",
		MaxSizeMB:      100,
		MaxBackups:     3,
		EnableRotation: true,
	}
}

// DefaultConfig возвращает конфигурацию по умолчанию
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
			RateLimit:      0,
			RateBurst:      10,
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
		Policy: DefaultPolicyConfig(),
		Audit:  DefaultAuditConfig(),
	}
}

// Load загружает конфигурацию из файла
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

	config.applyEnvOverrides()

	return config, nil
}

// Save сохраняет конфигурацию в файл
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

// applyEnvOverrides применяет переопределения из переменных окружения
func (c *Config) applyEnvOverrides() {
	if val := os.Getenv("MICROPKI_POLICY_REJECT_WILDCARDS"); val != "" {
		c.Policy.RejectWildcards = val == "true"
	}
	if val := os.Getenv("MICROPKI_POLICY_MAX_END_ENTITY_VALIDITY"); val != "" {
		fmt.Sscanf(val, "%d", &c.Policy.MaxEndEntityValidityDays)
	}
	if val := os.Getenv("MICROPKI_SERVER_RATE_LIMIT"); val != "" {
		fmt.Sscanf(val, "%f", &c.Server.RateLimit)
	}
	if val := os.Getenv("MICROPKI_SERVER_RATE_BURST"); val != "" {
		fmt.Sscanf(val, "%d", &c.Server.RateBurst)
	}
}

// ExampleConfig создает пример конфигурационного файла
func ExampleConfig() string {
	return `# MicroPKI Configuration Example

database:
  path: "./pki/micropki.db"
  wal_mode: true
  cache_size: 2000

server:
  host: "127.0.0.1"
  port: 8080
  cert_dir: "./pki/certs"
  enable_cors: true
  allowed_origins:
    - "*"
  rate_limit: 2
  rate_burst: 3

pki:
  default_key_type: "rsa"
  default_key_size: 4096
  root_validity_days: 3650
  int_validity_days: 1825
  cert_validity_days: 365
  out_dir: "./pki"

logging:
  level: "info"
  file: ""
  json_format: false

policy:
  min_rsa_key_size_root_ca: 4096
  min_rsa_key_size_intermediate_ca: 3072
  min_rsa_key_size_end_entity: 2048
  min_ecc_key_size_root_ca: 384
  min_ecc_key_size_intermediate_ca: 384
  min_ecc_key_size_end_entity: 256
  max_root_validity_days: 3650
  max_intermediate_validity_days: 1825
  max_end_entity_validity_days: 365
  reject_wildcards: true
  allowed_san_types_for_server:
    - "dns"
    - "ip"
  allowed_san_types_for_client:
    - "dns"
    - "email"
  allowed_san_types_for_code_signing:
    - "dns"
    - "uri"

audit:
  log_path: "./pki/audit/audit.log"
  chain_path: "./pki/audit/chain.dat"
  max_size_mb: 100
  max_backups: 3
  enable_rotation: true
`
}
