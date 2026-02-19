package tests

import (
	"os"
	"os/exec"
	"testing"
)

func TestSprint2Requirements(t *testing.T) {
	// Проверяем существование скрипта
	if _, err := os.Stat("./scripts/test-sprint2.sh"); err != nil {
		t.Skip("Skipping integration test: test-sprint2.sh not found")
	}

	// Запускаем shell скрипт
	cmd := exec.Command("/bin/bash", "./scripts/test-sprint2.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("Sprint 2 tests failed: %v", err)
	}
}
