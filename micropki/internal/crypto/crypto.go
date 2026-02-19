// Package crypto предоставляет криптографические операции для MicroPKI.
// Все операции используют стандартную библиотеку Go и реализуют требования
// промышленной безопасности.
//
// Пакет включает:
//   - Генерацию криптостойких ключевых пар (RSA, ECC)
//   - Шифрование/расшифрование закрытых ключей с использованием AES-256-GCM
//   - Сохранение и загрузку ключей в PEM-формате
//   - Безопасное затирание чувствительных данных в памяти
//
// Все криптографические операции соответствуют рекомендациям OWASP и NIST.
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

// KeyPair содержит приватный и публичный ключи.
// Используется как контейнер для результатов генерации ключей.
type KeyPair struct {
	// PrivateKey - закрытый ключ (RSA или ECDSA)
	PrivateKey crypto.PrivateKey

	// PublicKey - открытый ключ, соответствующий закрытому
	PublicKey crypto.PublicKey
}

// GenerateKeyPair генерирует криптографически безопасную ключевую пару.
// Соответствует требованиям PKI-1.
//
// Поддерживаемые типы и размеры:
//   - RSA: 2048 или 4096 бит
//   - ECC: P-256 (256 бит) или P-384 (384 бит)
//
// Параметры:
//   - keyType: тип ключа ("rsa" или "ecc")
//   - keySize: размер ключа в битах
//
// Возвращает:
//   - *KeyPair: структуру с ключевой парой
//   - error: ошибку, если параметры неверны или генерация не удалась
func GenerateKeyPair(keyType string, keySize int) (*KeyPair, error) {
	switch keyType {
	case "rsa":
		if keySize != 2048 && keySize != 4096 {
			return nil, fmt.Errorf("размер RSA ключа должен быть 2048 или 4096 бит, получен %d", keySize)
		}

		// Генерация RSA ключа
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

		// Генерация ECDSA ключа
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

// encryptPrivateKey шифрует приватный ключ с использованием AES-256-GCM.
// Использует PBKDF2 с 600,000 итераций (рекомендация OWASP) для получения
// ключа из парольной фразы.
//
// Формат выходных данных: ASN.1 структура {Salt, Nonce, Ciphertext}
//
// Параметры:
//   - keyBytes: байты ключа в формате PKCS#8
//   - passphrase: парольная фраза для шифрования
//
// Возвращает:
//   - []byte: зашифрованные данные в ASN.1 формате
//   - error: ошибку, если шифрование не удалось
func encryptPrivateKey(keyBytes []byte, passphrase []byte) ([]byte, error) {
	// Генерация соли для PBKDF2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ошибка генерации соли: %w", err)
	}

	// Использование PBKDF2 для получения ключа из пароля
	// 600,000 итераций - рекомендация OWASP
	derivedKey := pbkdf2.Key(passphrase, salt, 600000, 32, sha256.New)

	// Генерация случайного nonce для AES-GCM
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	// Создание AES шифра
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES шифра: %w", err)
	}

	// Создание GCM режима
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Шифрование данных
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

// decryptPrivateKey расшифровывает приватный ключ, зашифрованный encryptPrivateKey.
//
// Параметры:
//   - encryptedData: зашифрованные данные в ASN.1 формате
//   - passphrase: парольная фраза для расшифровки
//
// Возвращает:
//   - []byte: расшифрованные байты ключа
//   - error: ошибку, если расшифровка не удалась
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

	// Получение ключа из пароля с той же солью
	derivedKey := pbkdf2.Key(passphrase, enc.Salt, 600000, 32, sha256.New)

	// Создание AES шифра
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES шифра: %w", err)
	}

	// Создание GCM режима
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Расшифровка
	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return plaintext, nil
}

// SaveEncryptedPrivateKey сохраняет приватный ключ в зашифрованном PEM формате.
// Ключ шифруется с использованием AES-256-GCM и сохраняется с правами доступа 0600.
//
// Параметры:
//   - privateKey: закрытый ключ для сохранения
//   - filename: имя файла для сохранения
//   - passphrase: парольная фраза для шифрования
//
// Возвращает:
//   - error: ошибку, если сохранение не удалось
func SaveEncryptedPrivateKey(privateKey crypto.PrivateKey, filename string, passphrase []byte) error {
	// Маршалинг приватного ключа в PKCS#8 DER формат
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

	// Шифрование ключа
	encryptedData, err := encryptPrivateKey(keyBytes, passphrase)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ключа: %w", err)
	}

	// Создание PEM блока
	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
	}

	// Создание файла с ограниченными правами
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("ошибка создания файла ключа: %w", err)
	}
	defer file.Close()

	// Запись PEM
	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("ошибка записи PEM: %w", err)
	}

	return nil
}

// LoadEncryptedPrivateKey загружает и расшифровывает приватный ключ из PEM файла.
//
// Параметры:
//   - filename: имя файла с зашифрованным ключом
//   - passphrase: парольная фраза для расшифровки
//
// Возвращает:
//   - crypto.PrivateKey: расшифрованный закрытый ключ
//   - error: ошибку, если загрузка или расшифровка не удались
func LoadEncryptedPrivateKey(filename string, passphrase []byte) (crypto.PrivateKey, error) {
	// Чтение PEM файла
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла ключа: %w", err)
	}

	// Декодирование PEM блока
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("ошибка декодирования PEM")
	}

	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("неверный тип PEM блока: %s", block.Type)
	}

	// Расшифровка ключа
	keyBytes, err := decryptPrivateKey(block.Bytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки ключа: %w", err)
	}

	// Парсинг PKCS#8 ключа
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга ключа: %w", err)
	}

	return key, nil
}

// SavePrivateKeyUnencrypted сохраняет приватный ключ в незашифрованном PEM формате.
// ВНИМАНИЕ: Использовать только для тестовых или нечувствительных ключей!
// Ключ сохраняется с правами доступа 0600.
//
// Параметры:
//   - privateKey: закрытый ключ для сохранения
//   - filename: имя файла для сохранения
//
// Возвращает:
//   - error: ошибку, если сохранение не удалось
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
			return fmt.Errorf("не удалось маршалировать ECDSA ключ: %w", err)
		}
		blockType = "EC PRIVATE KEY"
	default:
		// Попытка использовать PKCS#8 как запасной вариант
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("не удалось маршалировать ключ: %w", err)
		}
		blockType = "PRIVATE KEY"
	}

	block := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("не удалось создать файл ключа: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("не удалось записать PEM: %w", err)
	}

	return nil
}

// VerifyKeyPair проверяет, что приватный ключ соответствует публичному.
// Поддерживает RSA и ECDSA ключи.
//
// Параметры:
//   - privateKey: закрытый ключ для проверки
//   - publicKey: открытый ключ для проверки
//
// Возвращает:
//   - error: ошибку, если ключи не соответствуют или тип не поддерживается
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

// SecureZero безопасно затирает байтовый слайс, перезаписывая его нулями.
// Используется для очистки чувствительных данных (пароли, ключи) в памяти.
//
// Параметры:
//   - data: байтовый слайс для затирания
func SecureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
