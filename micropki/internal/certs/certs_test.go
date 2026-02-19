// Package certs_test содержит тесты для операций с сертификатами.
// Тесты проверяют:
//   - Парсинг DN в различных форматах
//   - Генерацию серийных номеров
//   - Создание шаблонов сертификатов
//   - Соответствие сертификатов ключам
//
// Все тесты используют табличный подход (table-driven tests) для
// обеспечения полноты покрытия и удобства добавления новых тест-кейсов.
package certs_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"micropki/micropki/internal/certs"
)

// TestParseDN_SlashFormat проверяет парсинг DN в слэш-формате.
// Тестирует:
//   - Корректные DN с одним и несколькими атрибутами
//   - Обработку пустой строки
//   - Обработку неверного формата
func TestParseDN_SlashFormat(t *testing.T) {
	t.Log("Тестирование парсинга DN в слэш-формате")

	testCases := []struct {
		name    string
		input   string
		wantCN  string
		wantO   string
		wantC   string
		wantErr bool
	}{
		{
			name:   "полный DN с тремя атрибутами",
			input:  "/CN=Test CA/O=Org/C=RU",
			wantCN: "Test CA",
			wantO:  "Org",
			wantC:  "RU",
		},
		{
			name:   "только CN",
			input:  "/CN=Simple",
			wantCN: "Simple",
		},
		{
			name:   "CN, OU и O",
			input:  "/CN=Test/OU=Dev/O=Org",
			wantCN: "Test",
			wantO:  "Org",
		},
		{
			name:    "пустая строка",
			input:   "",
			wantErr: true,
		},
		{
			name:    "неверный формат",
			input:   "/invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, err := certs.ParseDN(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Error("ожидалась ошибка, но её не произошло")
				}
				return
			}

			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}

			if name.CommonName != tc.wantCN {
				t.Errorf("CN: ожидался '%s', получен '%s'", tc.wantCN, name.CommonName)
			}

			if tc.wantO != "" && (len(name.Organization) == 0 || name.Organization[0] != tc.wantO) {
				t.Errorf("O: ожидался '%s', получен '%v'", tc.wantO, name.Organization)
			}

			if tc.wantC != "" && (len(name.Country) == 0 || name.Country[0] != tc.wantC) {
				t.Errorf("C: ожидался '%s', получен '%v'", tc.wantC, name.Country)
			}
		})
	}
}

// TestParseDN_CommaFormat проверяет парсинг DN в формате с запятыми.
// Тестирует различные комбинации атрибутов.
func TestParseDN_CommaFormat(t *testing.T) {
	t.Log("Тестирование парсинга DN в формате с запятыми")

	testCases := []struct {
		name    string
		input   string
		wantCN  string
		wantO   string
		wantC   string
		wantErr bool
	}{
		{
			name:   "полный DN с пробелами после запятых",
			input:  "CN=Test CA, O=Org, C=RU",
			wantCN: "Test CA",
			wantO:  "Org",
			wantC:  "RU",
		},
		{
			name:   "только CN",
			input:  "CN=Simple",
			wantCN: "Simple",
		},
		{
			name:   "CN, OU и O",
			input:  "CN=Test, OU=Dev, O=Org",
			wantCN: "Test",
			wantO:  "Org",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			name, err := certs.ParseDN(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Error("ожидалась ошибка, но её не произошло")
				}
				return
			}

			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}

			if name.CommonName != tc.wantCN {
				t.Errorf("CN: ожидался '%s', получен '%s'", tc.wantCN, name.CommonName)
			}

			if tc.wantO != "" && (len(name.Organization) == 0 || name.Organization[0] != tc.wantO) {
				t.Errorf("O: ожидался '%s', получен '%v'", tc.wantO, name.Organization)
			}
		})
	}
}

// TestGenerateSerialNumber проверяет генерацию серийных номеров.
// Тестирует:
//   - Уникальность последовательных номеров
//   - Положительность чисел
//   - Отсутствие ошибок при генерации
func TestGenerateSerialNumber(t *testing.T) {
	t.Log("Тестирование генерации серийного номера")

	// Генерация нескольких номеров и проверка их различий
	serial1, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatalf("ошибка генерации первого номера: %v", err)
	}

	serial2, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatalf("ошибка генерации второго номера: %v", err)
	}

	if serial1.Cmp(serial2) == 0 {
		t.Error("серийные номера не должны совпадать")
	}

	// Проверка положительности числа
	if serial1.Sign() <= 0 {
		t.Error("серийный номер должен быть положительным")
	}
}

// TestNewRootCATemplate проверяет создание шаблона корневого CA.
// Тестирует:
//   - Версию сертификата (должна быть 3)
//   - Наличие расширения IsCA
//   - Корректность BasicConstraints
//   - Наличие требуемых KeyUsage
func TestNewRootCATemplate(t *testing.T) {
	t.Log("Тестирование создания шаблона сертификата")

	// Создание тестовых данных
	subject := &pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"RU"},
	}

	serial, _ := certs.GenerateSerialNumber()
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

	// Генерация тестового ключа
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ключ: %v", err)
	}

	template := certs.NewRootCATemplate(
		subject, subject, serial,
		notBefore, notAfter,
		&privateKey.PublicKey,
	)

	// Проверка обязательных полей
	if template.Version != 2 {
		t.Errorf("Version: ожидался 2, получен %d", template.Version)
	}

	if !template.IsCA {
		t.Error("IsCA должно быть true")
	}

	if !template.BasicConstraintsValid {
		t.Error("BasicConstraintsValid должно быть true")
	}

	// Проверка KeyUsage
	required := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if template.KeyUsage&required != required {
		t.Error("KeyUsage должно включать CertSign и CRLSign")
	}
}

// TestCertificateMatchesPrivateKey проверяет соответствие сертификата ключу.
// Создаёт реальный сертификат и проверяет, что функция корректно определяет
// соответствие между сертификатом и использованным при его создании ключом.
func TestCertificateMatchesPrivateKey(t *testing.T) {
	t.Log("Тестирование соответствия сертификата ключу")

	// Создание ключей
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("не удалось сгенерировать ключ: %v", err)
	}

	// Создание шаблона
	subject := &pkix.Name{CommonName: "Test"}
	serial, _ := certs.GenerateSerialNumber()

	template := certs.NewRootCATemplate(
		subject, subject, serial,
		time.Now(), time.Now().AddDate(1, 0, 0),
		&privateKey.PublicKey,
	)

	// Создание сертификата
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ошибка парсинга сертификата: %v", err)
	}

	// Проверка соответствия
	err = certs.CertificateMatchesPrivateKey(cert, privateKey)
	if err != nil {
		t.Errorf("сертификат должен соответствовать ключу: %v", err)
	}
}
