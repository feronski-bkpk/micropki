// Package crypto_test содержит тесты для криптографических операций MicroPKI.
// Тесты проверяют:
//   - Генерацию ключевых пар всех поддерживаемых типов и размеров
//   - Корректность шифрования и расшифровки ключей
//   - Сохранение и загрузку ключей в различных форматах
//   - Проверку соответствия ключевых пар
//   - Безопасное затирание памяти
//   - Обработку граничных случаев и неверных параметров
//
// Все тесты используют табличный подход для обеспечения полноты покрытия.
package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// TestGenerateKeyPair проверяет генерацию ключевых пар всех поддерживаемых типов.
// Тестирует:
//   - Корректные комбинации типов и размеров
//   - Проверку типов сгенерированных ключей
//   - Соответствие размеров ключей запрошенным
func TestGenerateKeyPair(t *testing.T) {
	t.Log("Тестирование генерации ключевых пар")

	tests := []struct {
		name    string
		keyType string
		keySize int
		wantErr bool
	}{
		{"RSA 2048", "rsa", 2048, false},
		{"RSA 4096", "rsa", 4096, false},
		{"ECC 256", "ecc", 256, false},
		{"ECC 384", "ecc", 384, false},
		{"Неверный тип", "invalid", 2048, true},
		{"RSA неверный размер", "rsa", 1024, true},
		{"RSA неверный размер 3072", "rsa", 3072, true},
		{"ECC неверный размер", "ecc", 512, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKeyPair(tt.keyType, tt.keySize)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GenerateKeyPair() ожидалась ошибка, но получена nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateKeyPair() вернула ошибку: %v", err)
				return
			}

			if got == nil {
				t.Error("GenerateKeyPair() вернула nil KeyPair")
				return
			}

			// Проверка типа и размера ключа
			switch tt.keyType {
			case "rsa":
				priv, ok := got.PrivateKey.(*rsa.PrivateKey)
				if !ok {
					t.Error("приватный ключ не RSA")
				}
				if priv.N.BitLen() != tt.keySize {
					t.Errorf("размер RSA ключа = %d, ожидалось %d", priv.N.BitLen(), tt.keySize)
				}

				pub, ok := got.PublicKey.(*rsa.PublicKey)
				if !ok {
					t.Error("публичный ключ не RSA")
				}
				if pub.N.BitLen() != tt.keySize {
					t.Errorf("размер публичного RSA ключа = %d, ожидалось %d", pub.N.BitLen(), tt.keySize)
				}

			case "ecc":
				priv, ok := got.PrivateKey.(*ecdsa.PrivateKey)
				if !ok {
					t.Error("приватный ключ не ECDSA")
				}

				var expectedCurve elliptic.Curve
				if tt.keySize == 256 {
					expectedCurve = elliptic.P256()
				} else {
					expectedCurve = elliptic.P384()
				}

				if priv.Curve != expectedCurve {
					t.Error("приватный ключ использует неверную кривую")
				}

				pub, ok := got.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Error("публичный ключ не ECDSA")
				}
				if pub.Curve != expectedCurve {
					t.Error("публичный ключ использует неверную кривую")
				}
			}
		})
	}
}

// TestGenerateKeyPair_Invalid проверяет обработку неверных параметров
// при генерации ключевых пар.
func TestGenerateKeyPair_Invalid(t *testing.T) {
	t.Log("Тестирование неверных параметров")

	// Неверный размер RSA
	_, err := GenerateKeyPair("rsa", 1024)
	if err == nil {
		t.Error("ожидалась ошибка для неверного размера RSA 1024")
	}

	_, err = GenerateKeyPair("rsa", 3072)
	if err == nil {
		t.Error("ожидалась ошибка для неверного размера RSA 3072")
	}

	// Неверный размер ECC
	_, err = GenerateKeyPair("ecc", 512)
	if err == nil {
		t.Error("ожидалась ошибка для неверного размера ECC 512")
	}

	// Неверный тип
	_, err = GenerateKeyPair("invalid", 2048)
	if err == nil {
		t.Error("ожидалась ошибка для неверного типа ключа")
	}
}

// TestSaveAndLoadEncryptedPrivateKey проверяет полный цикл:
// генерация → шифрование → сохранение → загрузка → расшифровка → верификация.
func TestSaveAndLoadEncryptedPrivateKey(t *testing.T) {
	t.Log("Тестирование сохранения и загрузки зашифрованных ключей")

	// Генерация ключа
	keyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ключ: %v", err)
	}

	// Временный файл
	tmpFile := "test_key.pem"
	defer os.Remove(tmpFile)

	passphrase := []byte("test-passphrase-123")

	// Сохранение зашифрованного ключа
	err = SaveEncryptedPrivateKey(keyPair.PrivateKey, tmpFile, passphrase)
	if err != nil {
		t.Fatalf("SaveEncryptedPrivateKey() вернула ошибку: %v", err)
	}

	// Проверка прав доступа
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("не удалось получить информацию о файле: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("неверные права доступа: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	// Загрузка ключа
	loadedKey, err := LoadEncryptedPrivateKey(tmpFile, passphrase)
	if err != nil {
		t.Fatalf("LoadEncryptedPrivateKey() вернула ошибку: %v", err)
	}

	// Проверка соответствия ключей
	if err := VerifyKeyPair(loadedKey, keyPair.PublicKey); err != nil {
		t.Errorf("загруженный ключ не соответствует оригинальному: %v", err)
	}

	// Попытка загрузки с неправильным паролем
	_, err = LoadEncryptedPrivateKey(tmpFile, []byte("wrong-password"))
	if err == nil {
		t.Error("LoadEncryptedPrivateKey() с неправильным паролем должна вернуть ошибку")
	}
}

// TestSavePrivateKeyUnencrypted проверяет сохранение незашифрованных ключей.
func TestSavePrivateKeyUnencrypted(t *testing.T) {
	t.Log("Тестирование сохранения незашифрованных ключей")

	// Генерация RSA ключа
	rsaKeyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать RSA ключ: %v", err)
	}

	// Временный файл
	tmpFile := "test_key_unencrypted.pem"
	defer os.Remove(tmpFile)

	// Сохранение незашифрованного ключа
	err = SavePrivateKeyUnencrypted(rsaKeyPair.PrivateKey, tmpFile)
	if err != nil {
		t.Fatalf("SavePrivateKeyUnencrypted() вернула ошибку: %v", err)
	}

	// Проверка прав доступа
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("не удалось получить информацию о файле: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("неверные права доступа: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	// Чтение файла и проверка, что ключ не зашифрован
	pemData, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("не удалось прочитать файл: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("не удалось декодировать PEM")
	}

	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("неверный тип PEM блока: %s, ожидался RSA PRIVATE KEY", block.Type)
	}

	// Попытка распарсить ключ
	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("не удалось распарсить RSA ключ: %v", err)
	}

	// Тестирование ECC ключа
	eccKeyPair, err := GenerateKeyPair("ecc", 256)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ECC ключ: %v", err)
	}

	tmpFileECC := "test_key_ecc.pem"
	defer os.Remove(tmpFileECC)

	err = SavePrivateKeyUnencrypted(eccKeyPair.PrivateKey, tmpFileECC)
	if err != nil {
		t.Fatalf("SavePrivateKeyUnencrypted() для ECC вернула ошибку: %v", err)
	}

	// Проверка ECC ключа
	pemData, err = os.ReadFile(tmpFileECC)
	if err != nil {
		t.Fatalf("не удалось прочитать файл ECC: %v", err)
	}

	block, _ = pem.Decode(pemData)
	if block == nil {
		t.Fatal("не удалось декодировать PEM для ECC")
	}

	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("неверный тип PEM блока: %s, ожидался EC PRIVATE KEY", block.Type)
	}
}

// TestVerifyKeyPair проверяет функцию проверки соответствия ключевых пар.
func TestVerifyKeyPair(t *testing.T) {
	t.Log("Тестирование проверки соответствия ключей")

	// Генерация пары ключей
	keyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ключ: %v", err)
	}

	// Проверка соответствия
	err = VerifyKeyPair(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		t.Errorf("VerifyKeyPair() вернула ошибку для корректной пары: %v", err)
	}

	// Генерация другой пары
	otherPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать другой ключ: %v", err)
	}

	// Проверка несоответствия
	err = VerifyKeyPair(keyPair.PrivateKey, otherPair.PublicKey)
	if err == nil {
		t.Error("VerifyKeyPair() должна вернуть ошибку для несоответствующей пары")
	}
}

// TestSecureZero проверяет, что функция безопасного затирания действительно
// перезаписывает данные нулями.
func TestSecureZero(t *testing.T) {
	t.Log("Тестирование безопасного затирания памяти")

	data := []byte("secret-password-123")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	if bytes.Equal(data, original) {
		t.Error("SecureZero() не затерла данные")
	}

	// Проверка, что все байты стали нулевыми
	for i, b := range data {
		if b != 0 {
			t.Errorf("байт %d не затерт: %v", i, b)
		}
	}
}

// TestKeyGenerationEdgeCases проверяет граничные случаи генерации ключей.
func TestKeyGenerationEdgeCases(t *testing.T) {
	t.Log("Тестирование граничных случаев генерации ключей")

	// Пустой тип ключа
	_, err := GenerateKeyPair("", 2048)
	if err == nil {
		t.Error("пустой тип ключа должен вызывать ошибку")
	}

	// Нулевой размер
	_, err = GenerateKeyPair("rsa", 0)
	if err == nil {
		t.Error("нулевой размер ключа должен вызывать ошибку")
	}

	// Отрицательный размер
	_, err = GenerateKeyPair("rsa", -1)
	if err == nil {
		t.Error("отрицательный размер ключа должен вызывать ошибку")
	}
}
