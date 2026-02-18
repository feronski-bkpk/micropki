// Package certs_test содержит тесты для операций с сертификатами
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

func TestParseDN_SlashFormat(t *testing.T) {
	t.Log("Тестирование парсинга DN в слэш-формате")

	testCases := []struct {
		input   string
		wantCN  string
		wantO   string
		wantC   string
		wantErr bool
	}{
		{"/CN=Test CA/O=Org/C=RU", "Test CA", "Org", "RU", false},
		{"/CN=Simple", "Simple", "", "", false},
		{"/CN=Test/OU=Dev/O=Org", "Test", "Org", "", false},
		{"", "", "", "", true},
		{"/invalid", "", "", "", true},
	}

	for _, tc := range testCases {
		name, err := certs.ParseDN(tc.input)

		if tc.wantErr {
			if err == nil {
				t.Errorf("Для ввода '%s' ожидалась ошибка", tc.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Ошибка парсинга '%s': %v", tc.input, err)
			continue
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
	}
}

func TestParseDN_CommaFormat(t *testing.T) {
	t.Log("Тестирование парсинга DN в формате с запятыми")

	testCases := []struct {
		input   string
		wantCN  string
		wantO   string
		wantC   string
		wantErr bool
	}{
		{"CN=Test CA, O=Org, C=RU", "Test CA", "Org", "RU", false},
		{"CN=Simple", "Simple", "", "", false},
		{"CN=Test, OU=Dev, O=Org", "Test", "Org", "", false},
	}

	for _, tc := range testCases {
		name, err := certs.ParseDN(tc.input)

		if tc.wantErr {
			if err == nil {
				t.Errorf("Для ввода '%s' ожидалась ошибка", tc.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Ошибка парсинга '%s': %v", tc.input, err)
			continue
		}

		if name.CommonName != tc.wantCN {
			t.Errorf("CN: ожидался '%s', получен '%s'", tc.wantCN, name.CommonName)
		}
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	t.Log("Тестирование генерации серийного номера")

	// Генерируем несколько номеров и проверяем что они разные
	serial1, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatalf("Ошибка генерации: %v", err)
	}

	serial2, err := certs.GenerateSerialNumber()
	if err != nil {
		t.Fatalf("Ошибка генерации: %v", err)
	}

	if serial1.Cmp(serial2) == 0 {
		t.Error("Серийные номера не должны совпадать")
	}

	// Проверяем что номер положительный
	if serial1.Sign() <= 0 {
		t.Error("Серийный номер должен быть положительным")
	}
}

func TestNewRootCATemplate(t *testing.T) {
	t.Log("Тестирование создания шаблона сертификата")

	// Создаем тестовые данные
	subject := &pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"RU"},
	}

	serial, _ := certs.GenerateSerialNumber()
	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

	// Генерируем тестовый ключ
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := certs.NewRootCATemplate(
		subject, subject, serial,
		notBefore, notAfter,
		&privateKey.PublicKey,
	)

	// Проверяем обязательные поля
	if template.Version != 2 {
		t.Errorf("Version: ожидался 2, получен %d", template.Version)
	}

	if !template.IsCA {
		t.Error("IsCA должно быть true")
	}

	if !template.BasicConstraintsValid {
		t.Error("BasicConstraintsValid должно быть true")
	}

	// Проверяем KeyUsage
	required := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if template.KeyUsage&required != required {
		t.Error("KeyUsage должно включать CertSign и CRLSign")
	}
}

func TestCertificateMatchesPrivateKey(t *testing.T) {
	t.Log("Тестирование соответствия сертификата ключу")

	// Создаем ключи
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Создаем шаблон
	subject := &pkix.Name{CommonName: "Test"}
	serial, _ := certs.GenerateSerialNumber()

	template := certs.NewRootCATemplate(
		subject, subject, serial,
		time.Now(), time.Now().AddDate(1, 0, 0),
		&privateKey.PublicKey,
	)

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Ошибка парсинга сертификата: %v", err)
	}

	// Проверяем соответствие
	err = certs.CertificateMatchesPrivateKey(cert, privateKey)
	if err != nil {
		t.Errorf("Сертификат должен соответствовать ключу: %v", err)
	}
}
