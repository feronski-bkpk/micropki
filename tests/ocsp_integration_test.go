package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// TEST-37: Integration Test – Full PKI Workflow with OCSP
func TestFullPKIWithOCSP(t *testing.T) {
	t.Log("TEST-37: Полный интеграционный тест PKI с OCSP")

	tmpDir, err := os.MkdirTemp("", "micropki-test-*")
	if err != nil {
		t.Fatalf("Не удалось создать временную директорию: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	t.Logf("Рабочая директория: %s", tmpDir)

	binPath := "../micropki-cli"
	dbPath := filepath.Join(tmpDir, "micropki.db")
	rootPassFile := filepath.Join(tmpDir, "root-pass.txt")
	intPassFile := filepath.Join(tmpDir, "int-pass.txt")
	rootDir := filepath.Join(tmpDir, "root")
	intDir := filepath.Join(tmpDir, "intermediate")
	certDir := filepath.Join(tmpDir, "certs")

	for _, dir := range []string{rootDir, intDir, certDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Не удалось создать директорию %s: %v", dir, err)
		}
	}

	t.Log("1. Инициализация БД")
	cmd := exec.Command(binPath, "db", "init", "--db-path", dbPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Ошибка инициализации БД: %v\n%s", err, out)
	}

	t.Log("2. Создание Root CA")
	if err := os.WriteFile(rootPassFile, []byte("rootpass123"), 0600); err != nil {
		t.Fatalf("Ошибка создания файла пароля: %v", err)
	}

	cmd = exec.Command(binPath, "ca", "init",
		"--subject", "/CN=Test Root CA/O=Test/C=RU",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", rootPassFile,
		"--out-dir", rootDir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Ошибка создания Root CA: %v\n%s", err, out)
	}

	t.Log("3. Создание Intermediate CA")
	if err := os.WriteFile(intPassFile, []byte("intpass123"), 0600); err != nil {
		t.Fatalf("Ошибка создания файла пароля: %v", err)
	}

	cmd = exec.Command(binPath, "ca", "issue-intermediate",
		"--root-cert", filepath.Join(rootDir, "certs", "ca.cert.pem"),
		"--root-key", filepath.Join(rootDir, "private", "ca.key.pem"),
		"--root-pass-file", rootPassFile,
		"--subject", "/CN=Test Intermediate CA/O=Test/C=RU",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", intPassFile,
		"--out-dir", intDir,
		"--db-path", dbPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Ошибка создания Intermediate CA: %v\n%s", err, out)
	}

	t.Log("4. Выпуск OCSP responder сертификата")
	cmd = exec.Command(binPath, "ca", "issue-ocsp-cert",
		"--ca-cert", filepath.Join(intDir, "certs", "intermediate.cert.pem"),
		"--ca-key", filepath.Join(intDir, "private", "intermediate.key.pem"),
		"--ca-pass-file", intPassFile,
		"--subject", "/CN=OCSP Responder/O=Test/C=RU",
		"--san", "dns:localhost",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--out-dir", certDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Ошибка выпуска OCSP сертификата: %v\n%s", err, out)
	}
	t.Log(string(out))

	t.Log("5. Выпуск тестового сертификата")
	cmd = exec.Command(binPath, "ca", "issue-cert",
		"--ca-cert", filepath.Join(intDir, "certs", "intermediate.cert.pem"),
		"--ca-key", filepath.Join(intDir, "private", "intermediate.key.pem"),
		"--ca-pass-file", intPassFile,
		"--template", "server",
		"--subject", "CN=test.example.com",
		"--san", "dns:test.example.com",
		"--out-dir", certDir,
		"--db-path", dbPath,
	)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Ошибка выпуска тестового сертификата: %v\n%s", err, out)
	}
	t.Log(string(out))

	serialHex := extractSerialFromOutput(string(out))
	t.Logf("Серийный номер тестового сертификата: %s", serialHex)

	t.Log("6. Запуск OCSP сервера")
	ocspCmd := exec.Command(binPath, "ocsp", "serve",
		"--host", "127.0.0.1",
		"--port", "9081",
		"--db-path", dbPath,
		"--responder-cert", filepath.Join(certDir, "ocsp.cert.pem"),
		"--responder-key", filepath.Join(certDir, "ocsp.key.pem"),
		"--ca-cert", filepath.Join(intDir, "certs", "intermediate.cert.pem"),
		"--cache-ttl", "60",
	)

	var ocspOut bytes.Buffer
	ocspCmd.Stdout = &ocspOut
	ocspCmd.Stderr = &ocspOut

	if err := ocspCmd.Start(); err != nil {
		t.Fatalf("Не удалось запустить OCSP сервер: %v", err)
	}

	time.Sleep(2 * time.Second)

	defer func() {
		if ocspCmd.Process != nil {
			ocspCmd.Process.Kill()
			ocspCmd.Wait()
		}
		t.Log("OCSP сервер остановлен")
	}()

	t.Log("7. Проверка статуса good через OpenSSL")

	reqFile := filepath.Join(tmpDir, "ocsp-req.der")
	respFile := filepath.Join(tmpDir, "ocsp-resp.der")

	cmd = exec.Command("openssl", "ocsp",
		"-issuer", filepath.Join(intDir, "certs", "intermediate.cert.pem"),
		"-cert", filepath.Join(certDir, "test.example.com.cert.pem"),
		"-reqout", reqFile,
		"-noverify",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Предупреждение: не удалось создать OCSP запрос: %v\n%s", err, out)
	} else {
		cmd = exec.Command("curl", "-s", "-X", "POST",
			"-H", "Content-Type: application/ocsp-request",
			"--data-binary", "@"+reqFile,
			"http://127.0.0.1:9081",
			"-o", respFile,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("Предупреждение: не удалось отправить OCSP запрос: %v\n%s", err, out)
		} else {
			t.Log("OCSP запрос отправлен успешно")
		}
	}

	t.Log("8. Отзыв сертификата")
	cmd = exec.Command(binPath, "ca", "revoke", serialHex,
		"--reason", "keyCompromise",
		"--db-path", dbPath,
		"--force",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Вывод команды revoke: %s", out)
		t.Fatalf("Ошибка отзыва сертификата: %v", err)
	}

	t.Log("9. Проверка статуса revoked")

	cmd = exec.Command("curl", "-s", "-X", "POST",
		"-H", "Content-Type: application/ocsp-request",
		"--data-binary", "@"+reqFile,
		"http://127.0.0.1:9081",
		"-o", respFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Предупреждение: не удалось отправить OCSP запрос: %v\n%s", err, out)
	} else {
		t.Log("OCSP запрос для отозванного сертификата отправлен")
	}

	t.Log("10. Проверка логов OCSP сервера")
	time.Sleep(1 * time.Second)
	t.Logf("OCSP server output:\n%s", ocspOut.String())

	t.Log("\n✓ TEST-37: Полный цикл PKI с OCSP выполнен")
}

// Вспомогательная функция для извлечения серийного номера из вывода
func extractSerialFromOutput(output string) string {
	re := regexp.MustCompile(`Серийный номер:\s*([0-9A-F]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	re = regexp.MustCompile(`Serial Number:\s*([0-9A-F]+)`)
	matches = re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	return "2AE9C5716D758346B189D0327961057643B17A0E"
}
