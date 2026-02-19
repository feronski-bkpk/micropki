// Package crypto предоставляет криптографические операции для MicroPKI.
// Все операции используют стандартную библиотеку Go.
package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// KeyPair содержит приватный и публичный ключи
type KeyPair struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
}

// GenerateKeyPair генерирует ключевую пару согласно PKI-1
// Поддерживаемые типы: RSA (2048 или 4096) и ECC P-256 или P-384
func GenerateKeyPair(keyType string, keySize int) (*KeyPair, error) {
	switch keyType {
	case "rsa":
		if keySize != 2048 && keySize != 4096 {
			return nil, fmt.Errorf("размер RSA ключа должен быть 2048 или 4096 бит, получен %d", keySize)
		}

		// Генерируем RSA ключ
		privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации RSA ключа: %w", err)
		}

		return &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	case "ecc":
		if keySize != 256 && keySize != 384 {
			return nil, fmt.Errorf("размер ECC ключа должен быть 256 (P-256) или 384 (P-384), получен %d", keySize)
		}

		var curve elliptic.Curve
		if keySize == 256 {
			curve = elliptic.P256()
		} else {
			curve = elliptic.P384()
		}

		// Генерируем ECDSA ключ
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ошибка генерации ECC ключа: %w", err)
		}

		return &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil

	default:
		return nil, fmt.Errorf("неподдерживаемый тип ключа: %s", keyType)
	}
}

// encryptPrivateKey шифрует приватный ключ с использованием AES-256-GCM
func encryptPrivateKey(keyBytes []byte, passphrase []byte) ([]byte, error) {
	// Генерируем соль для PBKDF2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ошибка генерации соли: %w", err)
	}

	// Используем PBKDF2 для получения ключа из пароля
	// 600,000 итераций - рекомендация OWASP
	derivedKey := pbkdf2.Key(passphrase, salt, 600000, 32, sha256.New)

	// Генерируем случайный nonce для AES-GCM
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	// Создаем AES шифр
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES шифра: %w", err)
	}

	// Создаем GCM режим
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Шифруем данные
	ciphertext := gcm.Seal(nil, nonce, keyBytes, nil)

	// Структура для хранения зашифрованных данных
	type encryptedKey struct {
		Salt       []byte
		Nonce      []byte
		Ciphertext []byte
	}

	encrypted := encryptedKey{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	return asn1.Marshal(encrypted)
}

// decryptPrivateKey расшифровывает приватный ключ
func decryptPrivateKey(encryptedData []byte, passphrase []byte) ([]byte, error) {
	type encryptedKey struct {
		Salt       []byte
		Nonce      []byte
		Ciphertext []byte
	}

	var enc encryptedKey
	if _, err := asn1.Unmarshal(encryptedData, &enc); err != nil {
		return nil, fmt.Errorf("ошибка разбора зашифрованных данных: %w", err)
	}

	// Получаем ключ из пароля с той же солью
	derivedKey := pbkdf2.Key(passphrase, enc.Salt, 600000, 32, sha256.New)

	// Создаем AES шифр
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES шифра: %w", err)
	}

	// Создаем GCM режим
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Расшифровываем
	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return plaintext, nil
}

// SaveEncryptedPrivateKey сохраняет приватный ключ в зашифрованном PEM формате
func SaveEncryptedPrivateKey(privateKey crypto.PrivateKey, filename string, passphrase []byte) error {
	// Маршалим приватный ключ в PKCS#8 DER формат
	var keyBytes []byte
	var err error

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
	default:
		return fmt.Errorf("неподдерживаемый тип приватного ключа: %T", privateKey)
	}

	if err != nil {
		return fmt.Errorf("ошибка маршалинга ключа: %w", err)
	}

	// Шифруем ключ
	encryptedData, err := encryptPrivateKey(keyBytes, passphrase)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ключа: %w", err)
	}

	// Создаем PEM блок
	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
	}

	// Создаем файл с ограниченными правами
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("ошибка создания файла ключа: %w", err)
	}
	defer file.Close()

	// Записываем PEM
	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("ошибка записи PEM: %w", err)
	}

	return nil
}

// LoadEncryptedPrivateKey загружает и расшифровывает приватный ключ из PEM файла
func LoadEncryptedPrivateKey(filename string, passphrase []byte) (crypto.PrivateKey, error) {
	// Читаем PEM файл
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла ключа: %w", err)
	}

	// Декодируем PEM блок
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("ошибка декодирования PEM")
	}

	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("неверный тип PEM блока: %s", block.Type)
	}

	// Расшифровываем ключ
	keyBytes, err := decryptPrivateKey(block.Bytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки ключа: %w", err)
	}

	// Парсим PKCS#8 ключ
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга ключа: %w", err)
	}

	return key, nil
}

// SavePrivateKeyUnencrypted сохраняет приватный ключ в незашифрованном PEM формате
func SavePrivateKeyUnencrypted(privateKey crypto.PrivateKey, filename string) error {
	var keyBytes []byte
	var err error
	var blockType string

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		blockType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		blockType = "EC PRIVATE KEY"
	default:
		// Try PKCS#8 as fallback
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
		blockType = "PRIVATE KEY"
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("failed to write PEM: %w", err)
	}

	return nil
}

// VerifyKeyPair проверяет что приватный ключ соответствует публичному
func VerifyKeyPair(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) error {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("публичный ключ не RSA")
		}
		if priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E {
			return fmt.Errorf("несоответствие RSA ключей")
		}

	case *ecdsa.PrivateKey:
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("публичный ключ не ECDSA")
		}
		if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
			return fmt.Errorf("несоответствие ECDSA ключей")
		}
		if priv.PublicKey.Curve != pub.Curve {
			return fmt.Errorf("несоответствие кривой ECDSA")
		}

	default:
		return fmt.Errorf("неподдерживаемый тип ключа")
	}

	return nil
}

// SecureZero безопасно затирает байтовый слайс
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
