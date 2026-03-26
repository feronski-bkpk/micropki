package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// VerificationResult содержит результат проверки цепочки аудита
type VerificationResult struct {
	Valid          bool
	TotalEntries   int
	FirstCorrupted int
	ErrorMessage   string
	LastValidHash  string
}

var (
	integrityBroken = false
	integrityMutex  sync.RWMutex
)

// IsIntegrityBroken возвращает статус целостности
func IsIntegrityBroken() bool {
	integrityMutex.RLock()
	defer integrityMutex.RUnlock()
	return integrityBroken
}

// SetIntegrityBroken устанавливает статус целостности
func SetIntegrityBroken(broken bool) {
	integrityMutex.Lock()
	defer integrityMutex.Unlock()
	integrityBroken = broken
}

// VerifyChainWithBlock проверяет целостность и при нарушении блокирует операции
func VerifyChainWithBlock(logPath, chainPath string) (*VerificationResult, error) {
	result, err := VerifyChain(logPath, chainPath)
	if err != nil {
		return nil, err
	}

	if !result.Valid {
		SetIntegrityBroken(true)
	} else {
		SetIntegrityBroken(false)
	}

	return result, nil
}

// VerifyChain проверяет целостность всей цепочки аудита
func VerifyChain(logPath, chainPath string) (*VerificationResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл аудита: %w", err)
	}
	defer file.Close()

	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл цепочки: %w", err)
	}
	storedHash := string(chainData)

	scanner := bufio.NewScanner(file)
	var entries []LogEntry
	var prevHash string
	var firstCorrupted int = -1
	valid := true

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("ошибка разбора записи %d: %w", lineNum, err)
		}

		entries = append(entries, entry)

		if lineNum == 1 && entry.Integrity.PrevHash != "0000000000000000000000000000000000000000000000000000000000000000" {
			valid = false
			firstCorrupted = lineNum
			break
		}

		if prevHash != "" && entry.Integrity.PrevHash != prevHash {
			valid = false
			firstCorrupted = lineNum
			break
		}

		hashInput, err := canonicalJSONWithoutHash(entry)
		if err != nil {
			return nil, fmt.Errorf("ошибка создания канонического JSON для записи %d: %w", lineNum, err)
		}

		hash := sha256.Sum256(hashInput)
		computedHash := hex.EncodeToString(hash[:])

		if computedHash != entry.Integrity.Hash {
			valid = false
			firstCorrupted = lineNum
			break
		}

		prevHash = entry.Integrity.Hash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	result := &VerificationResult{
		Valid:        valid,
		TotalEntries: len(entries),
	}

	if valid && len(entries) > 0 {
		result.LastValidHash = entries[len(entries)-1].Integrity.Hash
		if result.LastValidHash != storedHash {
			result.Valid = false
			result.ErrorMessage = "последний хеш не соответствует сохраненному в chain.dat"
		}
	} else if firstCorrupted > 0 {
		result.FirstCorrupted = firstCorrupted
		result.ErrorMessage = fmt.Sprintf("повреждение обнаружено в записи %d", firstCorrupted)
	}

	return result, nil
}

// canonicalJSONWithoutHash создает канонический JSON без поля hash
func canonicalJSONWithoutHash(entry LogEntry) ([]byte, error) {
	tempEntry := entry
	tempEntry.Integrity.Hash = ""
	return json.Marshal(tempEntry)
}
