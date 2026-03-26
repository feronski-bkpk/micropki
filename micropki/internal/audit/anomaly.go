package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

type AnomalyResult struct {
	Detected      bool
	Anomalies     []string
	TotalRequests int
	PeakRate      int
	AvgRate       float64
	TimeWindow    time.Duration
	TimeSpan      time.Duration
}

// DetectAnomalies выполняет эвристический анализ журнала аудита
func DetectAnomalies(logPath string, timeWindowHours int) (*AnomalyResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть журнал: %w", err)
	}
	defer file.Close()

	result := &AnomalyResult{
		Detected:   false,
		Anomalies:  []string{},
		TimeWindow: time.Duration(timeWindowHours) * time.Hour,
	}

	operations := make(map[string]int)
	statuses := make(map[string]int)
	var timestamps []time.Time

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		t, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
		if err != nil {
			continue
		}

		timestamps = append(timestamps, t)
		operations[entry.Operation]++
		statuses[entry.Operation+"_"+entry.Status]++
	}

	if len(timestamps) == 0 {
		return result, nil
	}

	result.TotalRequests = len(timestamps)

	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i].Before(timestamps[j])
	})

	result.TimeSpan = timestamps[len(timestamps)-1].Sub(timestamps[0])

	peakRate := 0
	for i := 0; i < len(timestamps); i++ {
		count := 1
		for j := i + 1; j < len(timestamps) && timestamps[j].Sub(timestamps[i]) <= time.Minute; j++ {
			count++
		}
		if count > peakRate {
			peakRate = count
		}
	}
	result.PeakRate = peakRate

	if result.TimeSpan > 0 {
		result.AvgRate = float64(result.TotalRequests) / result.TimeSpan.Hours()
	}

	if result.PeakRate > 20 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Обнаружен всплеск активности: %d запросов за минуту (норма < 20)", result.PeakRate))
		result.Detected = true
	} else if result.PeakRate > 10 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Повышенная активность: %d запросов за минуту", result.PeakRate))
	}

	revokeCount := operations["revoke_certificate"]
	if revokeCount > 3 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Необычно много отзывов: %d за период (норма < 3)", revokeCount))
		result.Detected = true
	} else if revokeCount > 1 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Обнаружены отзывы: %d сертификатов", revokeCount))
	}

	errorCount := statuses["issue_certificate_failure"]
	if errorCount > 5 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Много ошибок при выпуске: %d (норма < 5)", errorCount))
		result.Detected = true
	} else if errorCount > 2 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Обнаружены ошибки при выпуске: %d", errorCount))
	}

	compromiseCount := operations["key_compromise"]
	if compromiseCount > 0 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Обнаружена компрометация ключей: %d событий", compromiseCount))
		result.Detected = true
	}

	totalIssues := statuses["issue_certificate_started"] + statuses["issue_certificate_success"] + statuses["issue_certificate_failure"]
	if totalIssues > 0 {
		failRate := float64(errorCount) / float64(totalIssues) * 100
		if failRate > 30 {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("Высокий процент ошибок: %.1f%% (%d из %d)", failRate, errorCount, totalIssues))
			result.Detected = true
		}
	}

	issueCount := operations["issue_certificate"]
	if issueCount > 10 && result.TimeSpan < time.Hour {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("Много выпусков: %d за %s", issueCount, result.TimeSpan.Round(time.Second)))
		result.Detected = true
	}

	return result, nil
}
