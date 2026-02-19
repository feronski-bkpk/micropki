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

			// Проверяем тип и размер ключа
			switch tt.keyType {
			case "rsa":
				priv, ok := got.PrivateKey.(*rsa.PrivateKey)
				if !ok {
					t.Error("Приватный ключ не RSA")
				}
				if priv.N.BitLen() != tt.keySize {
					t.Errorf("Размер RSA ключа = %d, ожидалось %d", priv.N.BitLen(), tt.keySize)
				}

				pub, ok := got.PublicKey.(*rsa.PublicKey)
				if !ok {
					t.Error("Публичный ключ не RSA")
				}
				if pub.N.BitLen() != tt.keySize {
					t.Errorf("Размер публичного RSA ключа = %d, ожидалось %d", pub.N.BitLen(), tt.keySize)
				}

			case "ecc":
				priv, ok := got.PrivateKey.(*ecdsa.PrivateKey)
				if !ok {
					t.Error("Приватный ключ не ECDSA")
				}

				var expectedCurve elliptic.Curve
				if tt.keySize == 256 {
					expectedCurve = elliptic.P256()
				} else {
					expectedCurve = elliptic.P384()
				}

				if priv.Curve != expectedCurve {
					t.Error("Приватный ключ использует неверную кривую")
				}

				pub, ok := got.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Error("Публичный ключ не ECDSA")
				}
				if pub.Curve != expectedCurve {
					t.Error("Публичный ключ использует неверную кривую")
				}
			}
		})
	}
}

func TestGenerateKeyPair_Invalid(t *testing.T) {
	t.Log("Тестирование неверных параметров")

	// Неверный размер RSA
	_, err := GenerateKeyPair("rsa", 1024)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного размера RSA 1024")
	}

	_, err = GenerateKeyPair("rsa", 3072)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного размера RSA 3072")
	}

	// Неверный размер ECC
	_, err = GenerateKeyPair("ecc", 512)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного размера ECC 512")
	}

	// Неверный тип
	_, err = GenerateKeyPair("invalid", 2048)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного типа ключа")
	}
}

func TestSaveAndLoadEncryptedPrivateKey(t *testing.T) {
	t.Log("Тестирование сохранения и загрузки зашифрованных ключей")

	// Генерируем ключ
	keyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать ключ: %v", err)
	}

	// Временный файл
	tmpFile := "test_key.pem"
	defer os.Remove(tmpFile)

	passphrase := []byte("test-passphrase-123")

	// Сохраняем зашифрованный ключ
	err = SaveEncryptedPrivateKey(keyPair.PrivateKey, tmpFile, passphrase)
	if err != nil {
		t.Fatalf("SaveEncryptedPrivateKey() вернула ошибку: %v", err)
	}

	// Проверяем права доступа
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Не удалось получить информацию о файле: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Неверные права доступа: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	// Загружаем ключ
	loadedKey, err := LoadEncryptedPrivateKey(tmpFile, passphrase)
	if err != nil {
		t.Fatalf("LoadEncryptedPrivateKey() вернула ошибку: %v", err)
	}

	// Проверяем соответствие ключей
	if err := VerifyKeyPair(loadedKey, keyPair.PublicKey); err != nil {
		t.Errorf("Загруженный ключ не соответствует оригинальному: %v", err)
	}

	// Пробуем загрузить с неправильным паролем
	_, err = LoadEncryptedPrivateKey(tmpFile, []byte("wrong-password"))
	if err == nil {
		t.Error("LoadEncryptedPrivateKey() с неправильным паролем должна вернуть ошибку")
	}
}

func TestSavePrivateKeyUnencrypted(t *testing.T) {
	t.Log("Тестирование сохранения незашифрованных ключей")

	// Генерируем RSA ключ
	rsaKeyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать RSA ключ: %v", err)
	}

	// Временный файл
	tmpFile := "test_key_unencrypted.pem"
	defer os.Remove(tmpFile)

	// Сохраняем незашифрованный ключ
	err = SavePrivateKeyUnencrypted(rsaKeyPair.PrivateKey, tmpFile)
	if err != nil {
		t.Fatalf("SavePrivateKeyUnencrypted() вернула ошибку: %v", err)
	}

	// Проверяем права доступа
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Не удалось получить информацию о файле: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Неверные права доступа: ожидалось 0600, получено %o", info.Mode().Perm())
	}

	// Читаем файл и проверяем, что ключ не зашифрован
	pemData, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Не удалось прочитать файл: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Не удалось декодировать PEM")
	}

	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("Неверный тип PEM блока: %s, ожидался RSA PRIVATE KEY", block.Type)
	}

	// Пробуем распарсить ключ
	_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Не удалось распарсить RSA ключ: %v", err)
	}

	// Тестируем ECC ключ
	eccKeyPair, err := GenerateKeyPair("ecc", 256)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать ECC ключ: %v", err)
	}

	tmpFileECC := "test_key_ecc.pem"
	defer os.Remove(tmpFileECC)

	err = SavePrivateKeyUnencrypted(eccKeyPair.PrivateKey, tmpFileECC)
	if err != nil {
		t.Fatalf("SavePrivateKeyUnencrypted() для ECC вернула ошибку: %v", err)
	}

	// Проверяем ECC ключ
	pemData, err = os.ReadFile(tmpFileECC)
	if err != nil {
		t.Fatalf("Не удалось прочитать файл ECC: %v", err)
	}

	block, _ = pem.Decode(pemData)
	if block == nil {
		t.Fatal("Не удалось декодировать PEM для ECC")
	}

	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("Неверный тип PEM блока: %s, ожидался EC PRIVATE KEY", block.Type)
	}
}

func TestVerifyKeyPair(t *testing.T) {
	t.Log("Тестирование проверки соответствия ключей")

	// Генерируем пару ключей
	keyPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать ключ: %v", err)
	}

	// Проверяем соответствие
	err = VerifyKeyPair(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		t.Errorf("VerifyKeyPair() вернула ошибку для корректной пары: %v", err)
	}

	// Генерируем другую пару
	otherPair, err := GenerateKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("Не удалось сгенерировать другой ключ: %v", err)
	}

	// Проверяем несоответствие
	err = VerifyKeyPair(keyPair.PrivateKey, otherPair.PublicKey)
	if err == nil {
		t.Error("VerifyKeyPair() должна вернуть ошибку для несоответствующей пары")
	}
}

func TestSecureZero(t *testing.T) {
	t.Log("Тестирование безопасного затирания памяти")

	data := []byte("secret-password-123")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	if bytes.Equal(data, original) {
		t.Error("SecureZero() не затерла данные")
	}

	// Проверяем, что все байты стали нулевыми
	for i, b := range data {
		if b != 0 {
			t.Errorf("Байт %d не затерт: %v", i, b)
		}
	}
}

func TestKeyGenerationEdgeCases(t *testing.T) {
	t.Log("Тестирование граничных случаев генерации ключей")

	// Пустой тип ключа
	_, err := GenerateKeyPair("", 2048)
	if err == nil {
		t.Error("Пустой тип ключа должен вызывать ошибку")
	}

	// Нулевой размер
	_, err = GenerateKeyPair("rsa", 0)
	if err == nil {
		t.Error("Нулевой размер ключа должен вызывать ошибку")
	}

	// Отрицательный размер
	_, err = GenerateKeyPair("rsa", -1)
	if err == nil {
		t.Error("Отрицательный размер ключа должен вызывать ошибку")
	}
}
