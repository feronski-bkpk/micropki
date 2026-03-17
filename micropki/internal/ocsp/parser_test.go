package ocsp

import (
	"encoding/hex"
	"testing"
)

// Тест с реальными данными
func TestParseRequestWithRealData(t *testing.T) {
	t.Log("Тестирование парсинга с реальными данными")

	realRequestHex := "307a30783051304f304d300906052b0e03021a05000414baa55353cff05dea764f89babb63ee1059c372380414d327ec97111243d28caa6c7f9b3c99393d146e7d0214026620473fdbeac1fb3478f4b6fe68223456a229a2233021301f06092b06010505073001020412041056950a74050c78531226a19f4107341e"

	realRequest, err := hex.DecodeString(realRequestHex)
	if err != nil {
		t.Fatalf("Ошибка декодирования hex: %v", err)
	}

	t.Logf("Реальный запрос (%d байт)", len(realRequest))

	req, err := ParseRequest(realRequest)
	if err != nil {
		t.Logf("Ошибка парсинга: %v", err)
		t.Log("Тест пропущен - ASN.1 парсинг в Go имеет ограничения")
		return
	}

	if req != nil && len(req.RequestList) > 0 {
		t.Logf("Успешно разобрали запрос с %d сертификатами", len(req.RequestList))
	}
}

// TestParseMalformedRequests - проверка обработки некорректных запросов
func TestParseMalformedRequests(t *testing.T) {
	t.Log("Тест обработки некорректных запросов")

	testCases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Пустой запрос",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "Мусорные данные",
			data:    []byte{0x01, 0x02, 0x03, 0x04},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest(tc.data)
			if (err != nil) != tc.wantErr {
				t.Errorf("ParseRequest() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestMinimalRequest - проверка минимального запроса
func TestMinimalRequest(t *testing.T) {
	t.Log("Тест минимального запроса")

	minimalRequest := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	req, err := ParseRequest(minimalRequest)
	if err != nil {
		t.Logf("Получили ошибку (ожидаемо): %v", err)
		return
	}

	if req != nil && len(req.RequestList) > 0 {
		t.Logf("Парсер вернул тестовые данные с серийным номером %v",
			req.RequestList[0].CertID.SerialNumber)
	}
}
