# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это профессиональный инструмент командной строки для создания и управления инфраструктурой публичных ключей (PKI) с поддержкой корневых и промежуточных центров сертификации, а также выпуска сертификатов различных типов с акцентом на безопасность, соответствие стандартам X.509 и простоту использования.

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
- [Примеры](#примеры)
- [Структура проекта](#структура-проекта)
- [Безопасность](#безопасность)
- [Тестирование](#тестирование)
- [Makefile команды](#makefile-команды)

## Возможности

### **Основные функции**
- **Генерация криптостойких ключей**:
  - RSA 2048 или 4096 бит
  - ECC P-256 или P-384
- **Создание самоподписанных X.509v3 сертификатов** со всеми необходимыми расширениями:
  - Basic Constraints (CA=TRUE, критическое)
  - Key Usage (keyCertSign, cRLSign, критическое)
  - Subject Key Identifier (SKI)
  - Authority Key Identifier (AKI)
- **Создание промежуточных центров сертификации** (Intermediate CA):
  - Подпись корневым CA
  - Настраиваемое ограничение длины пути (pathLenConstraint)
- **Выпуск сертификатов по шаблонам**:
  - **Server** - для TLS серверов с поддержкой Subject Alternative Names (SAN)
  - **Client** - для TLS клиентов
  - **Code Signing** - для подписи кода
- **Поддержка Subject Alternative Names (SAN)**:
  - DNS имена
  - IP адреса
  - Email адреса
  - URI
- **Подпись внешних CSR** (Certificate Signing Requests)
- **Безопасное хранение ключей**:
  - Шифрование AES-256-GCM с PBKDF2 (600,000 итераций)
  - Права доступа 0600 для ключей, 0700 для директорий
- **Подробное логирование** всех операций
- **Генерация политики безопасности** (policy.txt)
- **Проверка полной цепочки сертификатов**

### **Безопасность**
- Использование только криптостойких алгоритмов
- Защита от padding oracle атак (AES-GCM)
- Безопасное затирание паролей в памяти
- Проверка соответствия ключа и сертификата
- Верификация самоподписанных сертификатов
- Валидация цепочек сертификатов согласно RFC 5280

### **Технические детали**
- Написано на чистом Go (только стандартная библиотека + golang.org/x/crypto)
- Полное покрытие тестами (>70% в криптопакете)
- Кросс-платформенная компиляция (Linux, macOS, Windows)
- OpenSSL совместимость

## Быстрый старт

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/feronski-bkpk/micropki
cd micropki

# 2. Соберите проект
make build

# 3. Создайте корневой CA
echo "MyRootPass123" > root-pass.txt
./micropki-cli ca init \
  --subject "/CN=Мой Корневой CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file root-pass.txt \
  --out-dir ./pki/root \
  --validity-days 3650

# 4. Создайте промежуточный CA
echo "MyIntermediatePass456" > intermediate-pass.txt
./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file root-pass.txt \
  --subject "/CN=Мой Промежуточный CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file intermediate-pass.txt \
  --out-dir ./pki/intermediate

# 5. Выпустите серверный сертификат
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template server \
  --subject "CN=example.com" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs

# 6. Проверьте цепочку сертификатов
./micropki-cli ca verify-chain \
  --leaf ./pki/certs/example.com.cert.pem \
  --intermediate ./pki/intermediate/certs/intermediate.cert.pem \
  --root ./pki/root/certs/ca.cert.pem
```

## Установка

### Сборка из исходников

```bash
# Требования: Go 1.21 или выше
git clone https://github.com/yourusername/micropki.git
cd micropki
make build
sudo make install  # опционально, установит в /usr/local/bin
```

## Использование

### Команда `ca init`

Создание нового корневого центра сертификации.

```bash
./micropki-cli ca init [параметры]
```

**Обязательные параметры:**

| Параметр | Описание | Пример |
|----------|----------|--------|
| `--subject` | Distinguished Name | `/CN=My CA/O=Org/C=RU` |
| `--key-size` | Размер ключа | `4096` (RSA) или `384` (ECC) |
| `--passphrase-file` | Файл с паролем | `./secrets/pass.txt` |

**Опциональные параметры:**

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--out-dir` | Выходная директория | `./pki` |
| `--validity-days` | Срок действия (дни) | `3650` (10 лет) |
| `--log-file` | Файл для логов | stderr |
| `--force` | Перезапись существующих файлов | `false` |

### Команда `ca issue-intermediate`

Создание промежуточного центра сертификации, подписанного корневым CA.

```bash
./micropki-cli ca issue-intermediate [параметры]
```

**Обязательные параметры:**

| Параметр | Описание | Пример |
|----------|----------|--------|
| `--root-cert` | Путь к сертификату корневого CA | `./pki/root/certs/ca.cert.pem` |
| `--root-key` | Путь к ключу корневого CA | `./pki/root/private/ca.key.pem` |
| `--root-pass-file` | Файл с паролем корневого CA | `./root-pass.txt` |
| `--subject` | Distinguished Name для промежуточного CA | `/CN=Intermediate CA` |
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--key-size` | Размер ключа | `4096` (RSA) или `384` (ECC) |
| `--passphrase-file` | Файл с паролем для промежуточного CA | `./intermediate-pass.txt` |

**Опциональные параметры:**

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--out-dir` | Выходная директория | `./pki` |
| `--validity-days` | Срок действия (дни) | `1825` (5 лет) |
| `--pathlen` | Ограничение длины пути | `0` |

### Команда `ca issue-cert`

Выпуск конечного сертификата, подписанного промежуточным CA.

```bash
./micropki-cli ca issue-cert [параметры]
```

**Обязательные параметры:**

| Параметр | Описание | Пример |
|----------|----------|--------|
| `--ca-cert` | Сертификат промежуточного CA | `./pki/intermediate/certs/intermediate.cert.pem` |
| `--ca-key` | Ключ промежуточного CA | `./pki/intermediate/private/intermediate.key.pem` |
| `--ca-pass-file` | Пароль промежуточного CA | `./intermediate-pass.txt` |
| `--template` | Шаблон: `server`, `client`, `code_signing` | `server` |

**Опциональные параметры:**

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--subject` | Distinguished Name | - |
| `--san` | Subject Alternative Name (можно несколько) | - |
| `--csr` | Путь к внешнему CSR для подписи | - |
| `--out-dir` | Выходная директория | `./pki/certs` |
| `--validity-days` | Срок действия (дни) | `365` |
| `--key-type` | Тип ключа для генерации | `rsa` |
| `--key-size` | Размер ключа для генерации | `2048` (RSA) или `256` (ECC) |

### Команда `ca verify`

Проверка сертификата.

```bash
./micropki-cli ca verify --cert ./pki/certs/cert.pem
```

### Команда `ca verify-chain`

Проверка полной цепочки сертификатов.

```bash
./micropki-cli ca verify-chain \
  --leaf ./pki/certs/leaf.cert.pem \
  --intermediate ./pki/intermediate/certs/intermediate.cert.pem \
  --root ./pki/root/certs/ca.cert.pem
```

## Примеры

### Пример 1: Создание полной PKI иерархии

```bash
# Создание Root CA
echo "RootPass123" > root-pass.txt
./micropki-cli ca init \
  --subject "/CN=Production Root CA/O=My Company/C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file root-pass.txt \
  --out-dir ./pki/root

# Создание Intermediate CA
echo "IntermediatePass456" > intermediate-pass.txt
./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file root-pass.txt \
  --subject "/CN=Production Intermediate CA/O=My Company/C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file intermediate-pass.txt \
  --out-dir ./pki/intermediate

# Выпуск серверного сертификата для example.com
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template server \
  --subject "CN=example.com" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs
```

### Пример 2: Выпуск клиентского сертификата

```bash
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template client \
  --subject "CN=Alice Smith" \
  --san email:alice@example.com \
  --san dns:client.example.com \
  --out-dir ./pki/certs
```

### Пример 3: Выпуск сертификата для подписи кода

```bash
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template code_signing \
  --subject "CN=My Code Signing Certificate" \
  --out-dir ./pki/certs
```

### Пример 4: Подпись внешнего CSR

```bash
# Создание CSR с OpenSSL
openssl req -new -newkey rsa:2048 -nodes \
  -keyout private.key -out request.csr \
  -subj "/CN=external.example.com"

# Подпись CSR промежуточным CA
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template server \
  --csr request.csr \
  --out-dir ./pki/certs
```

### Пример 5: Проверка с OpenSSL

```bash
# Просмотр содержимого сертификата
openssl x509 -in ./pki/certs/example.com.cert.pem -text -noout

# Проверка цепочки
openssl verify -CAfile ./pki/root/certs/ca.cert.pem \
  -untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  ./pki/certs/example.com.cert.pem

# Проверка расширений (SAN, EKU)
openssl x509 -in ./pki/certs/example.com.cert.pem -text -noout | grep -A 10 "X509v3 extensions:"
```

## Структура проекта

```
micropki/
├── micropki/                       # Основной пакет
│   ├── cmd/
│   │   └── micropki/               # Точка входа CLI
│   │       └── main.go
│   └── internal/                   # Внутренние пакеты
│       ├── ca/                     # Логика CA (Root и Intermediate)
│       ├── certs/                  # X.509 операции
│       ├── chain/                  # Проверка цепочек сертификатов
│       ├── crypto/                 # Криптография
│       ├── csr/                    # Обработка CSR
│       ├── san/                    # Обработка Subject Alternative Names
│       └── templates/              # Шаблоны сертификатов
├── tests/                          # Интеграционные тесты
├── scripts/                        # Вспомогательные скрипты
├── Makefile                        # Автоматизация сборки
├── go.mod                          # Зависимости Go
└── README.md                       # Этот файл
```

**Выходная структура PKI (`--out-dir`):**
```
pki/
├── root/
│   ├── private/
│   │   └── ca.key.pem                # Зашифрованный ключ Root CA (0600)
│   ├── certs/
│   │   └── ca.cert.pem               # Сертификат Root CA (0644)
│   └── policy.txt                    # Политика Root CA
├── intermediate/
│   ├── private/
│   │   └── intermediate.key.pem      # Зашифрованный ключ Intermediate CA (0600)
│   ├── certs/
│   │   └── intermediate.cert.pem     # Сертификат Intermediate CA (0644)
│   └── policy.txt                    # Политика Intermediate CA
└── certs/
    ├── example.com.cert.pem          # Серверный сертификат (0644)
    ├── example.com.key.pem           # Незашифрованный ключ (0600) - WARNING!
    ├── alice_example.com.cert.pem    # Клиентский сертификат
    └── MicroPKI_Code_Signer.cert.pem # Сертификат для подписи кода
```

## Безопасность

### Криптографические стандарты

| Компонент | Технология | Обоснование |
|-----------|------------|-------------|
| **RSA ключи** | 2048/4096 бит | Промышленный стандарт, устойчив к квантовым атакам |
| **ECC ключи** | P-256/P-384 (NIST) | Рекомендовано NSA |
| **Шифрование ключей CA** | AES-256-GCM | Аутентифицированное шифрование, защита от padding oracle |
| **Ключи конечных субъектов** | Незашифрованные | Для совместимости с веб-серверами (предупреждение в логах) |
| **Производные ключи** | PBKDF2, 600,000 итераций | OWASP рекомендации |
| **Серийные номера** | 160 бит CSPRNG | Предотвращение коллизий |

### Рекомендации по эксплуатации

1. **Храните пароли надёжно**: Используйте менеджеры паролей
2. **Резервное копирование**: Сохраняйте копии `root/private/` и `intermediate/private/` в защищённом месте
3. **Ограничьте доступ**: Только администраторы PKI должны иметь доступ к приватным ключам CA
4. **Мониторинг**: Анализируйте логи на предмет подозрительной активности
5. **Регулярные проверки**: Периодически проверяйте цепочки сертификатов
6. **Внимание**: Ключи конечных сертификатов хранятся **незашифрованными** - обеспечьте их безопасность на целевом сервере

## Тестирование

### Запуск тестов

```bash
# Модульные тесты
make test

# Подробный вывод
make test-verbose

# С покрытием
make test-coverage

# Интеграционные тесты (скрипт)
./scripts/test-sprint2.sh
```

## Makefile команды

| Команда | Описание |
|---------|----------|
| `make build` | Собрать бинарный файл |
| `make clean` | Удалить все сгенерированные файлы |
| `make test` | Запустить модульные тесты |
| `make test-verbose` | Запустить тесты с подробным выводом |
| `make test-coverage` | Запустить тесты с отчётом о покрытии |
| `make lint` | Проверить стиль кода |
| `make fmt` | Отформатировать код |
| `make vet` | Запустить статический анализ |
| `make example` | Создать пример CA |
| `make verify` | Проверить созданный сертификат |
| `make release` | Создать релизные сборки для всех платформ |
| `make security-check` | Проверить уязвимости |
| `make check-all` | Запустить все проверки |
| `make help` | Показать все команды |

### Пример полного цикла разработки

```bash
# 1. Форматирование и линтинг
make fmt lint vet

# 2. Тестирование
make test-coverage

# 3. Сборка
make build

# 4. Проверка функционала
make example verify
./scripts/test-sprint2.sh

# 5. Создание релиза
make release

# 6. Очистка
make clean
```

## Участие в разработке

1. Форкните репозиторий
2. Создайте ветку (`git checkout -b feature/amazing-feature`)
3. Закоммитьте изменения (`git commit -m 'Add amazing feature'`)
4. Запушьте ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request