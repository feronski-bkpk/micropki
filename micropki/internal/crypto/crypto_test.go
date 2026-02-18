// Package crypto_test содержит тесты для криптографических операций
package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"micropki/micropki/internal/crypto"
)

func TestGenerateKeyPair_RSA(t *testing.T) {
	t.Log("Тестирование генерации RSA ключа")

	kp, err := crypto.GenerateKeyPair("rsa", 4096)
	if err != nil {
		t.Fatalf("Ошибка генерации RSA ключа: %v", err)
	}

	if kp.PrivateKey == nil {
		t.Error("Приватный ключ не должен быть nil")
	}

	if kp.PublicKey == nil {
		t.Error("Публичный ключ не должен быть nil")
	}

	// Проверяем соответствие ключей
	if err := crypto.VerifyKeyPair(kp.PrivateKey, kp.PublicKey); err != nil {
		t.Errorf("Ключи не соответствуют друг другу: %v", err)
	}
}

func TestGenerateKeyPair_ECC(t *testing.T) {
	t.Log("Тестирование генерации ECC ключа")

	kp, err := crypto.GenerateKeyPair("ecc", 384)
	if err != nil {
		t.Fatalf("Ошибка генерации ECC ключа: %v", err)
	}

	if kp.PrivateKey == nil {
		t.Error("Приватный ключ не должен быть nil")
	}

	if kp.PublicKey == nil {
		t.Error("Публичный ключ не должен быть nil")
	}

	// Проверяем соответствие ключей
	if err := crypto.VerifyKeyPair(kp.PrivateKey, kp.PublicKey); err != nil {
		t.Errorf("Ключи не соответствуют друг другу: %v", err)
	}
}

func TestGenerateKeyPair_Invalid(t *testing.T) {
	t.Log("Тестирование неверных параметров")

	// Неверный тип ключа
	_, err := crypto.GenerateKeyPair("invalid", 4096)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного типа ключа")
	}

	// Неверный размер для RSA
	_, err = crypto.GenerateKeyPair("rsa", 2048)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного размера RSA")
	}

	// Неверный размер для ECC
	_, err = crypto.GenerateKeyPair("ecc", 256)
	if err == nil {
		t.Error("Ожидалась ошибка для неверного размера ECC")
	}
}

func TestSaveAndLoadEncryptedKey(t *testing.T) {
	t.Log("Тестирование сохранения и загрузки зашифрованного ключа")

	// Создаем временную директорию
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key.pem")
	passphrase := []byte("test-passphrase-123")

	// Генерируем ключ
	kp, err := crypto.GenerateKeyPair("rsa", 4096)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Сохраняем зашифрованный ключ
	err = crypto.SaveEncryptedPrivateKey(kp.PrivateKey, keyPath, passphrase)
	if err != nil {
		t.Fatalf("Ошибка сохранения ключа: %v", err)
	}

	// Проверяем что файл создан
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("Файл ключа не создан: %v", err)
	}

	// Загружаем ключ
	loadedKey, err := crypto.LoadEncryptedPrivateKey(keyPath, passphrase)
	if err != nil {
		t.Fatalf("Ошибка загрузки ключа: %v", err)
	}

	// Проверяем что ключи совпадают
	if err := crypto.VerifyKeyPair(loadedKey, kp.PublicKey); err != nil {
		t.Errorf("Загруженный ключ не соответствует оригиналу: %v", err)
	}
}

func TestSecureZero(t *testing.T) {
	t.Log("Тестирование безопасного затирания памяти")

	data := []byte("secret-data")
	crypto.SecureZero(data)

	// Проверяем что все байты обнулены
	for i, b := range data {
		if b != 0 {
			t.Errorf("Байт [%d] не обнулен: %v", i, b)
		}
	}
}
