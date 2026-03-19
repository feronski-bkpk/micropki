package cli

import (
	"fmt"
	"log"
)

// RunClient обрабатывает команду 'client'
func RunClient(args []string, logger *log.Logger) error {
	if len(args) < 1 {
		printClientUsage()
		return nil
	}

	switch args[0] {
	case "gen-csr":
		return RunClientGenCSR(args[1:], logger)
	case "request-cert":
		return RunClientRequestCert(args[1:], logger)
	case "validate":
		return RunClientValidate(args[1:], logger)
	case "check-status":
		return RunClientCheckStatus(args[1:], logger)
	case "help", "--help", "-h":
		printClientUsage()
		return nil
	default:
		return fmt.Errorf("неизвестная подкоманда '%s' для 'client'", args[0])
	}
}

// printClientUsage выводит справку по client командам
func printClientUsage() {
	fmt.Println("Клиентские команды MicroPKI:")
	fmt.Println("\n  client gen-csr          Генерация закрытого ключа и CSR")
	fmt.Println("      --subject             Различающееся имя (обязательно)")
	fmt.Println("      --key-type            Тип ключа: rsa или ecc (по умолчанию: rsa)")
	fmt.Println("      --key-size            Размер ключа (RSA: 2048/4096, ECC: 256/384)")
	fmt.Println("      --san                 Альтернативные имена субъекта (можно несколько)")
	fmt.Println("      --out-key             Выходной файл для ключа (по умолчанию: ./key.pem)")
	fmt.Println("      --out-csr             Выходной файл для CSR (по умолчанию: ./request.csr.pem)")

	fmt.Println("\n  client request-cert     Отправка CSR в CA и получение сертификата")
	fmt.Println("      --csr                 Путь к файлу CSR (обязательно)")
	fmt.Println("      --template            Шаблон: server, client, code_signing (обязательно)")
	fmt.Println("      --ca-url              URL репозитория (обязательно)")
	fmt.Println("      --out-cert            Выходной файл для сертификата (по умолчанию: ./cert.pem)")
	fmt.Println("      --api-key             API ключ (опционально)")
	fmt.Println("      --timeout             Таймаут HTTP запроса в секундах (по умолчанию: 30)")

	fmt.Println("\n  client validate         Проверка цепочки сертификатов")
	fmt.Println("      --cert                Путь к конечному сертификату (обязательно)")
	fmt.Println("      --untrusted           Промежуточные сертификаты (можно несколько)")
	fmt.Println("      --trusted             Доверенный корневой CA (по умолчанию: ./pki/certs/ca.cert.pem)")
	fmt.Println("      --crl                 Проверить CRL (файл или URL)")
	fmt.Println("      --ocsp                Выполнить OCSP проверку")
	fmt.Println("      --mode                Режим: chain или full (по умолчанию: full)")
	fmt.Println("      --format              Формат: text или json (по умолчанию: text)")
	fmt.Println("      --validation-time     Время проверки (RFC3339)")

	fmt.Println("\n  client check-status     Проверка статуса отзыва")
	fmt.Println("      --cert                Путь к сертификату (обязательно)")
	fmt.Println("      --ca-cert             Сертификат издателя (обязательно)")
	fmt.Println("      --crl                 CRL файл или URL (опционально)")
	fmt.Println("      --ocsp-url            URL OCSP ответчика (опционально)")
}
