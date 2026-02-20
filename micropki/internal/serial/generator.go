// Package serial предоставляет функциональность для генерации уникальных
// серийных номеров X.509 сертификатов с гарантией глобальной уникальности.
package serial

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Generator создает уникальные серийные номера с гарантией отсутствия коллизий.
// Использует 64-битный составной формат:
//   - Старшие 32 бита: временная метка Unix (секунды)
//   - Младшие 32 бита: криптостойкое случайное число
//
// Дополнительно проверяет уникальность в базе данных.
type Generator struct {
	db     *sql.DB
	mu     sync.Mutex
	lastTs uint32
}

// NewGenerator создает новый генератор серийных номеров с подключением к БД.
func NewGenerator(db *sql.DB) *Generator {
	return &Generator{
		db: db,
	}
}

// SerialNumber представляет серийный номер X.509 сертификата.
type SerialNumber struct {
	Int   *big.Int
	Hex   string
	Bytes []byte
}

// Generate создает новый уникальный серийный номер.
// Процесс:
// 1. Берет текущую временную метку Unix (32 бита)
// 2. Генерирует 32 бита криптостойкой случайности
// 3. Комбинирует в 64-битное число
// 4. Проверяет уникальность в БД (если дубликат, повторяет с новой случайностью)
func (g *Generator) Generate() (*SerialNumber, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	maxAttempts := 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Получаем текущую временную метку (32 бита)
		ts := uint32(time.Now().Unix())

		// Гарантируем монотонность временной метки
		if ts <= g.lastTs {
			ts = g.lastTs + 1
		}
		g.lastTs = ts

		// Генерируем 32 бита случайности
		randomBytes := make([]byte, 4)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, fmt.Errorf("не удалось сгенерировать случайные данные: %w", err)
		}
		random := binary.BigEndian.Uint32(randomBytes)

		// Комбинируем в 64-битное число
		// Старшие 32 бита = ts, младшие 32 бита = random
		combined := (uint64(ts) << 32) | uint64(random)

		// Конвертируем в *big.Int
		intVal := new(big.Int).SetUint64(combined)

		// Проверяем уникальность в БД
		unique, err := g.checkUniqueness(intVal)
		if err != nil {
			return nil, err
		}
		if unique {
			// Конвертируем в hex строку (без префикса 0x)
			hexStr := hex.EncodeToString(intVal.Bytes())

			// Возвращаем результат
			return &SerialNumber{
				Int:   intVal,
				Hex:   hexStr,
				Bytes: intVal.Bytes(),
			}, nil
		}
	}

	return nil, fmt.Errorf("не удалось сгенерировать уникальный серийный номер после %d попыток", maxAttempts)
}

// GenerateWithEntropy генерирует серийный номер с указанным количеством бит энтропии.
// Полезно для тестирования или особых требований.
func (g *Generator) GenerateWithEntropy(bits int) (*SerialNumber, error) {
	if bits < 20 || bits > 160 {
		return nil, fmt.Errorf("бит энтропии должно быть между 20 и 160")
	}

	bytes := make([]byte, bits/8)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать случайные данные: %w", err)
	}

	// Сбрасываем старший бит для положительного числа
	bytes[0] &= 0x7F

	intVal := new(big.Int).SetBytes(bytes)

	// Проверяем уникальность
	unique, err := g.checkUniqueness(intVal)
	if err != nil {
		return nil, err
	}
	if !unique {
		// Если неуникально, пробуем снова рекурсивно
		return g.GenerateWithEntropy(bits)
	}

	return &SerialNumber{
		Int:   intVal,
		Hex:   hex.EncodeToString(intVal.Bytes()),
		Bytes: intVal.Bytes(),
	}, nil
}

// checkUniqueness проверяет, уникален ли серийный номер в базе данных.
func (g *Generator) checkUniqueness(serial *big.Int) (bool, error) {
	if g.db == nil {
		// Если БД не подключена, считаем что уникален
		return true, nil
	}

	hexStr := hex.EncodeToString(serial.Bytes())

	var count int
	err := g.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE serial_hex = ?", hexStr).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке уникальности серийного номера: %w", err)
	}

	return count == 0, nil
}

// FromHex создает SerialNumber из hex строки.
func FromHex(hexStr string) (*SerialNumber, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("неверный hex формат: %w", err)
	}

	intVal := new(big.Int).SetBytes(bytes)

	return &SerialNumber{
		Int:   intVal,
		Hex:   hexStr,
		Bytes: bytes,
	}, nil
}

// FromBigInt создает SerialNumber из *big.Int.
func FromBigInt(intVal *big.Int) *SerialNumber {
	return &SerialNumber{
		Int:   intVal,
		Hex:   hex.EncodeToString(intVal.Bytes()),
		Bytes: intVal.Bytes(),
	}
}
