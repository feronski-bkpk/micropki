# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это инструмент командной строки для создания и управления инфраструктурой публичных ключей (PKI) с поддержкой корневых и промежуточных центров сертификации, выпуска сертификатов различных типов, системой управления списками отзыва сертификатов (CRL), OCSP-ответчиком для проверки статуса сертификатов в реальном времени, а также полным набором клиентских инструментов для генерации CSR, запросов на выпуск сертификатов и проверки цепочек доверия.

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
  - [Команды CA](#команды-ca)
  - [Команды аудита](#команды-аудита)
  - [Команды тестирования](#команды-тестирования)
  - [Клиентские команды](#клиентские-команды)
  - [Команды управления CRL](#команды-управления-crl)
  - [Команды OCSP](#команды-ocsp)
  - [Команды базы данных](#команды-базы-данных)
  - [Команды репозитория](#команды-репозитория)
- [Политики безопасности](#политики-безопасности)
- [Система аудита](#система-аудита)
- [Certificate Transparency (CT)](#certificate-transparency-ct)
- [Rate Limiting](#rate-limiting)
- [Компрометация ключей](#компрометация-ключей)
- [Детекция аномалий](#детекция-аномалий)
- [Примеры](#примеры)
- [Структура проекта](#структура-проекта)
- [API Репозитория](#api-репозитория)
- [OCSP Responder API](#ocsp-responder-api)
- [Безопасность](#безопасность)
- [Тестирование](#тестирование)
- [Makefile команды](#makefile-команды)

## Возможности

### **Основные функции**
- **Генерация криптостойких ключей**:
  - RSA 2048 или 4096 бит
  - ECC P-256 или P-384
- **Создание самоподписанных X.509v3 сертификатов**
- **Создание промежуточных центров сертификации**
- **Выпуск сертификатов по шаблонам** (Server, Client, Code Signing, OCSP)
- **Поддержка Subject Alternative Names (SAN)**
- **Клиентские инструменты** (генерация CSR, запрос сертификатов, валидация)
- **Полная поддержка CRL версии 2 (v2)** согласно RFC 5280
- **OCSP-ответчик** согласно RFC 6960
- **SQLite база данных** для хранения сертификатов
- **HTTP репозиторий** для распространения сертификатов и CRL

### **Новые функции Спринта 7**

#### **Аудит с криптографической целостностью**
- NDJSON формат журнала (`./pki/audit/audit.log`)
- SHA-256 хеш-цепочка для защиты от подделки
- Файл `chain.dat` с последним хешем
- Команды: `audit query`, `audit verify`

#### **Принудительное применение политик безопасности**
- **Размеры ключей**:
  - RSA: Корневой CA ≥ 4096, Промежуточный ≥ 3072, Конечный ≥ 2048
  - ECC: Корневой/Промежуточный ≥ P-384, Конечный ≥ P-256
- **Сроки действия**:
  - Корневой CA: до 10 лет (3650 дней)
  - Промежуточный CA: до 5 лет (1825 дней)
  - Конечные сертификаты: до 1 года (365 дней)
- **Ограничения SAN**:
  - Wildcard блокируется по умолчанию
  - Проверка разрешенных типов для каждого шаблона
- **Алгоритмы подписи**: SHA-1 и MD5 запрещены
- **Ограничение длины пути**: промежуточные CA имеют pathLen=0

#### **Rate Limiting**
- Token bucket алгоритм
- Конфигурация через флаги `--rate-limit` и `--rate-burst`
- HTTP статус 429 Too Many Requests
- Заголовок `Retry-After`

#### **Certificate Transparency (CT) симуляция**
- Файл `./pki/audit/ct.log`
- Запись каждого выпущенного сертификата
- Серийный номер, субъект, отпечаток SHA-256

#### **Компрометация ключей**
- Команда `ca compromise` для симуляции
- Таблица `compromised_keys` в БД
- Экстренное обновление CRL
- Блокировка выпуска с скомпрометированными ключами

#### **Детекция аномалий**
- Команда `audit detect-anomalies`
- Обнаружение всплесков активности (>20 запросов/мин)
- Выявление большого количества ошибок (>5)
- Отслеживание компрометаций
- Анализ процента ошибок (>30%)

#### **Конфигурация через YAML/TOML**
- Поддержка флага `--config`
- Настраиваемые политики безопасности
- Конфигурация rate limiting и аудита

## Быстрый старт

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/feronski-bkpk/micropki
cd micropki

# 2. Соберите проект
make build

# 3. Создайте полную PKI иерархию с аудитом
make example-full

# 4. Проверьте целостность аудита
./micropki-cli audit verify

# 5. Сгенерируйте CSR и получите сертификат
./micropki-cli client gen-csr \
  --subject "CN=test.example.com" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:test.example.com \
  --out-key test.key.pem \
  --out-csr test.csr.pem

# 6. Запустите репозиторий (в отдельном терминале)
./micropki-cli repo serve --host 127.0.0.1 --port 8080

# 7. В другом терминале отправьте CSR
./micropki-cli client request-cert \
  --csr test.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert test.cert.pem

# 8. Проверьте CT-журнал
cat ./pki/audit/ct.log

# 9. Проанализируйте аномалии
./micropki-cli audit detect-anomalies --window 1

# 10. Остановите сервер (Ctrl+C в терминале с сервером)
```

## Установка

### Сборка из исходников

```bash
# Требования: Go 1.21 или выше
git clone https://github.com/feronski-bkpk/micropki
cd micropki
make build
sudo make install  # опционально, установит в /usr/local/bin
```

## Использование

### Команды CA

#### `ca init`
Создание нового корневого центра сертификации.

```bash
./micropki-cli ca init [параметры]
```

**Обязательные параметры:**
- `--subject` - Distinguished Name
- `--key-size` - размер ключа (4096 для RSA, 384 для ECC)
- `--passphrase-file` - файл с паролем

#### `ca issue-intermediate`
Создание промежуточного CA.

```bash
./micropki-cli ca issue-intermediate [параметры]
```

#### `ca issue-cert`
Выпуск конечного сертификата с проверкой политик.

```bash
./micropki-cli ca issue-cert [параметры]
```

**Политики применяются автоматически:**
- Размер ключа RSA ≥ 2048 бит
- Срок действия ≤ 365 дней
- Wildcard SAN блокируется
- Типы SAN проверяются по шаблону

#### `ca compromise`
Симуляция компрометации закрытого ключа.

```bash
./micropki-cli ca compromise --cert <путь> [--reason <причина>] [--force]
```

### Команды аудита

#### `audit query`
Поиск и отображение записей журнала аудита.

```bash
./micropki-cli audit query [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--from` | Начальная временная метка (ISO 8601) | - |
| `--to` | Конечная временная метка | - |
| `--level` | Уровень: INFO, WARNING, ERROR, AUDIT | - |
| `--operation` | Фильтр по типу операции | - |
| `--serial` | Фильтр по серийному номеру | - |
| `--format` | Формат: `table`, `json`, `csv` | `table` |
| `--verify` | Проверить целостность | `false` |

#### `audit verify`
Проверка целостности всего журнала аудита.

```bash
./micropki-cli audit verify [--log-file <путь>] [--chain-file <путь>]
```

**Вывод при успехе:**
```
✓ Статус: ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА
Последний хеш: 9d289403d622787b9c6aae09ad6348b2f8310a51127a5cb20a63eb62d6a38f27
```

#### `audit detect-anomalies`
Эвристический анализ аномалий в журнале аудита.

```bash
./micropki-cli audit detect-anomalies [--window <часы>]
```

**Обнаруживаемые аномалии:**
- Всплеск активности (>20 запросов/мин)
- Много ошибок (>5 ошибок выпуска)
- Компрометации ключей
- Высокий процент ошибок (>30%)

### Команды тестирования

#### `test rsa-1024`
Тест блокировки RSA-1024 ключа.

```bash
./micropki-cli test rsa-1024
```

**Ожидаемый результат:**
```
Тест ПРОЙДЕН: RSA-1024 заблокирован при генерации
   Ошибка: размер RSA ключа должен быть 2048 или 4096 бит, получен 1024
```

### Клиентские команды

#### `client gen-csr`
Генерация закрытого ключа и CSR.

```bash
./micropki-cli client gen-csr [параметры]
```

#### `client request-cert`
Отправка CSR в репозиторий и получение сертификата.

```bash
./micropki-cli client request-cert [параметры]
```

#### `client validate`
Проверка цепочки сертификатов.

```bash
./micropki-cli client validate [параметры]
```

#### `client check-status`
Проверка статуса отзыва сертификата (OCSP → CRL).

```bash
./micropki-cli client check-status [параметры]
```

### Команды управления CRL

#### `ca revoke <serial>`
Отзыв сертификата по серийному номеру.

```bash
./micropki-cli ca revoke <serial> [--reason <причина>] [--db-path <путь>]
```

#### `ca gen-crl`
Генерация CRL для указанного CA.

```bash
./micropki-cli ca gen-crl --ca <root|intermediate> [--next-update <дни>]
```

### Команды OCSP

#### `ocsp serve`
Запуск OCSP-ответчика.

```bash
./micropki-cli ocsp serve [параметры]
```

### Команды базы данных

#### `db init`
Инициализация базы данных SQLite.

```bash
./micropki-cli db init --db-path ./pki/micropki.db
```

### Команды репозитория

#### `repo serve`
Запуск HTTP сервера репозитория с rate limiting.

```bash
./micropki-cli repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --rate-limit 2 \
  --rate-burst 3
```

## Политики безопасности

### Размеры ключей

| Тип | RSA | ECC |
|-----|-----|-----|
| Корневой CA | ≥ 4096 бит | ≥ P-384 |
| Промежуточный CA | ≥ 3072 бит | ≥ P-384 |
| Конечный субъект | ≥ 2048 бит | ≥ P-256 |

### Сроки действия

| Тип | Максимальный срок |
|-----|------------------|
| Корневой CA | 10 лет (3650 дней) |
| Промежуточный CA | 5 лет (1825 дней) |
| Конечные сертификаты | 1 год (365 дней) |

### Ограничения SAN

| Шаблон | Разрешенные типы | Запрещенные типы |
|--------|-----------------|------------------|
| `server` | dns, ip | email, uri |
| `client` | dns, email | ip, uri |
| `code_signing` | dns, uri | ip, email |

### Алгоритмы подписи
- SHA-1 и MD5 запрещены
- Требуется SHA-256 или выше

## Система аудита

### Формат записи (NDJSON)

```json
{
  "timestamp": "2026-03-25T15:04:05.123456Z",
  "level": "AUDIT",
  "operation": "issue_certificate",
  "status": "success",
  "message": "Сертификат успешно выпущен",
  "metadata": {
    "serial": "2A7F8B3C...",
    "subject": "CN=example.com",
    "template": "server"
  },
  "integrity": {
    "prev_hash": "abc123...",
    "hash": "def456..."
  }
}
```

### Хеш-цепочка
- Каждая запись содержит SHA-256 хеш предыдущей записи
- Первая запись имеет `prev_hash = "0"*64`
- Отдельный файл `chain.dat` хранит последний хеш

### Обязательные события аудита
- Инициализация CA
- Выпуск сертификата (успех/ошибка)
- Отзыв сертификата
- Компрометация ключа
- Нарушение политик
- Генерация CRL
- Запуск/остановка OCSP

## Certificate Transparency (CT)

Файл `./pki/audit/ct.log` содержит записи в формате:

```
2026-03-25T15:04:05Z    2a7f8b3c...    CN=example.com    b3ad3957...    CN=Test Intermediate CA
```

Каждая запись включает:
- Временную метку (ISO 8601)
- Серийный номер (hex)
- DN субъекта
- SHA-256 отпечаток сертификата
- DN издателя

## Rate Limiting

### Алгоритм Token Bucket
- `--rate-limit`: запросов в секунду
- `--rate-burst`: максимальный размер ведра

### Ответ при превышении
```
HTTP/1.1 429 Too Many Requests
Retry-After: 10
Content-Type: text/plain

Too Many Requests
```

## Компрометация ключей

### Процесс компрометации
1. Отзыв сертификата с причиной `keyCompromise`
2. Добавление записи в таблицу `compromised_keys`
3. Экстренное обновление CRL
4. Запись в аудит

### Блокировка
При попытке выпуска нового сертификата с скомпрометированным ключом:
```
нарушение политики: ключ скомпрометирован, выпуск запрещен
```

## Детекция аномалий

### Пороги обнаружения

| Тип аномалии | Порог |
|--------------|-------|
| Всплеск активности | >20 запросов/мин |
| Много ошибок | >5 ошибок |
| Компрометации | >0 |
| Процент ошибок | >30% |

### Пример вывода

```
=== Анализ аномалий в журнале аудита ===
Временное окно анализа: 1 часов
Фактический период записей: 4m33s
Всего запросов: 63
Пиковая нагрузка: 50 запросов/мин

ОБНАРУЖЕНЫ АНОМАЛИИ:
  - Обнаружен всплеск активности: 50 запросов за минуту
  - Много ошибок при выпуске: 16 (норма < 5)
  - Высокий процент ошибок: 41.0% (16 из 39)
```

## Примеры

### Пример 1: Полный рабочий процесс с аудитом и политиками

```bash
# 1. Инициализация PKI
./micropki-cli ca init \
  --subject "CN=Test Root CA" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file <(echo -n "rootpass") \
  --out-dir ./pki

./micropki-cli ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file <(echo -n "rootpass") \
  --subject "CN=Test Intermediate CA" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file <(echo -n "intpass") \
  --out-dir ./pki \
  --db-path ./pki/micropki.db

# 2. Выпуск сертификата с проверкой политик
./micropki-cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file <(echo -n "intpass") \
  --template server \
  --subject "CN=example.com" \
  --san "dns:example.com" \
  --out-dir ./pki/certs \
  --validity-days 365 \
  --db-path ./pki/micropki.db

# 3. Проверка аудита
./micropki-cli audit query --operation issue_certificate --format table

# 4. Проверка целостности
./micropki-cli audit verify
```

### Пример 2: Тестирование политик безопасности

```bash
# Wildcard (должна быть ошибка)
./micropki-cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file <(echo -n "intpass") \
  --template server \
  --subject "CN=*.bad.com" \
  --san "dns:*.bad.com" \
  --out-dir /tmp
# Ошибка: wildcard SAN запрещен

# Превышение срока (должна быть ошибка)
./micropki-cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file <(echo -n "intpass") \
  --template server \
  --subject "CN=bad.local" \
  --san "dns:bad.local" \
  --validity-days 400 \
  --out-dir /tmp
# Ошибка: срок превышает максимальный
```

### Пример 3: Rate limiting

```bash
# Запуск сервера с ограничением
./micropki-cli repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --rate-limit 2 \
  --rate-burst 3

# Быстрые запросы
for i in {1..5}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/health
done
# Вывод: 200, 200, 200, 200, 429
```

### Пример 4: Компрометация и блокировка

```bash
# Создание сертификата
./micropki-cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file <(echo -n "intpass") \
  --template server \
  --subject "CN=compromise-test.local" \
  --san "dns:compromise-test.local" \
  --out-dir ./pki/certs

# Симуляция компрометации
./micropki-cli ca compromise \
  --cert ./pki/certs/compromise-test.local.cert.pem \
  --reason keyCompromise \
  --force

# Попытка выпуска с тем же ключом (будет заблокирована)
openssl req -new -key ./pki/certs/compromise-test.local.key.pem \
  -subj "/CN=blocked.local" \
  -addext "subjectAltName=DNS:blocked.local" \
  -out /tmp/blocked.csr.pem

./micropki-cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file <(echo -n "intpass") \
  --template server \
  --subject "CN=blocked.local" \
  --csr /tmp/blocked.csr.pem \
  --out-dir /tmp
# Ошибка: ключ скомпрометирован, выпуск запрещен
```

### Пример 5: Детекция аномалий

```bash
# Генерация множества ошибок
for i in {1..15}; do
  ./micropki-cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file <(echo -n "intpass") \
    --template server \
    --subject "CN=error-$i.local" \
    --san "dns:*.error-$i.local" \
    --out-dir /tmp > /dev/null 2>&1
done

# Анализ аномалий
./micropki-cli audit detect-anomalies --window 1
# Вывод обнаружит: много ошибок, высокий процент ошибок
```

## Структура проекта

```
micropki/
├── micropki/                         # Основной пакет
│   ├── cmd/
│   │   └── micropki/                 # Точка входа CLI
│   │       └── main.go
│   └── internal/                     # Внутренние пакеты
│       ├── audit/                    # Аудит с хеш-цепочкой
│       ├── policy/                   # Политики безопасности
│       ├── ratelimit/                # Rate limiting
│       ├── transparency/             # CT-журнал
│       ├── compromise/               # Компрометация ключей
│       ├── ca/                       # Логика CA
│       ├── certs/                    # X.509 операции
│       ├── chain/                    # Проверка цепочек
│       ├── cli/                      # Клиентские команды
│       ├── config/                   # Конфигурация (YAML/TOML)
│       ├── crl/                      # CRL генерация
│       ├── crypto/                   # Криптография
│       ├── csr/                      # Обработка CSR
│       ├── database/                 # SQLite база данных
│       ├── ocsp/                     # OCSP функциональность
│       ├── repository/               # HTTP репозиторий
│       ├── revocation/               # Проверка отзыва
│       ├── san/                      # Subject Alternative Names
│       ├── serial/                   # Генератор серийных номеров
│       ├── templates/                # Шаблоны сертификатов
│       └── validation/               # Валидация цепочек
├── tests/                            # Интеграционные тесты
├── scripts/                          # Вспомогательные скрипты
├── Makefile                          # Автоматизация сборки
├── go.mod                            # Зависимости Go
└── README.md                         # Этот файл
```

**Выходная структура PKI (`--out-dir`):**
```
pki/
├── micropki.db                       # База данных SQLite
├── audit/                            # Журналы аудита
│   ├── audit.log                     # NDJSON журнал с хеш-цепочкой
│   ├── chain.dat                     # Последний хеш цепочки
│   └── ct.log                        # Certificate Transparency журнал
├── crl/                              # CRL файлы
│   ├── root.crl.pem
│   └── intermediate.crl.pem
├── root/
│   ├── private/
│   │   └── ca.key.pem                # Зашифрованный ключ Root CA (0600)
│   ├── certs/
│   │   └── ca.cert.pem               # Сертификат Root CA (0644)
│   └── policy.txt
├── intermediate/
│   ├── private/
│   │   └── intermediate.key.pem      # Зашифрованный ключ Intermediate CA (0600)
│   ├── certs/
│   │   └── intermediate.cert.pem     # Сертификат Intermediate CA (0644)
│   └── policy.txt
└── certs/
    ├── ocsp.cert.pem                 # OCSP responder сертификат
    ├── ocsp.key.pem                  # Незашифрованный ключ OCSP (0600)
    ├── example.com.cert.pem          # Тестовый сертификат
    ├── example.com.key.pem           # Незашифрованный ключ (0600)
    └── ...
```

## API Репозитория

### Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/health` | Проверка работоспособности |
| GET | `/certificate/<serial>` | Получение сертификата |
| GET | `/ca/root` | Корневой CA сертификат |
| GET | `/ca/intermediate` | Промежуточный CA сертификат |
| GET | `/crl` | Получение CRL |
| POST | `/request-cert?template=<template>` | Отправка CSR и получение сертификата |

## OCSP Responder API

### Эндпоинт

| Метод | Путь | Content-Type | Описание |
|-------|------|--------------|----------|
| POST | `/` | `application/ocsp-request` | OCSP запрос |

## Безопасность

### Криптографические стандарты

| Компонент | Технология |
|-----------|------------|
| **RSA ключи** | 2048/4096 бит (политика) |
| **ECC ключи** | P-256/P-384 (политика) |
| **Шифрование ключей CA** | AES-256-GCM |
| **Хеш-цепочка аудита** | SHA-256 |
| **Серийные номера** | 160 бит энтропии |
| **Права доступа к ключам** | 0600 (только владелец) |

### Политики безопасности

| Проверка | Действие при нарушении |
|----------|------------------------|
| Размер RSA < 2048 | Отказ выпуска + аудит |
| Размер ECC < 256 | Отказ выпуска + аудит |
| Срок > 365 дней | Отказ выпуска + аудит |
| Wildcard SAN | Отказ выпуска + аудит |
| Запрещенный тип SAN | Отказ выпуска + аудит |
| SHA-1 подпись | Отказ выпуска + аудит |

### Защита от компрометации

- Таблица `compromised_keys` с хешами открытых ключей
- Блокировка выпуска при обнаружении скомпрометированного ключа
- Экстренное обновление CRL при компрометации
- Аудит всех компрометаций

## Тестирование

### Запуск тестов

```bash
# Модульные тесты
make test

# Тесты Спринта 7
make test-sprint7

# Полный тест аудита
make test-audit

# Тест rate limiting
make test-rate-limit

# Тест CT-журнала
make test-ct

# Тест компрометации
make test-compromise

# Тест детекции аномалий
make test-detection-anomalies

# Тест RSA-1024
make test-rsa-1024

# Все тесты
make test-all
```

## Makefile команды

### Основные цели

| Команда | Описание |
|---------|----------|
| `make build` | Собрать бинарный файл |
| `make clean` | Удалить все сгенерированные файлы |
| `make test` | Запустить модульные тесты |
| `make test-all` | Все тесты (включая Спринт 7) |

### Цели Спринта 7

| Команда | Описание |
|---------|----------|
| `make test-sprint7` | Полный интеграционный тест Спринта 7 |
| `make test-audit` | Тест аудита с хеш-цепочкой |
| `make test-audit-verify` | Проверка целостности аудита |
| `make test-audit-verify-fake` | Тест обнаружения подделки |
| `make test-policy` | Тест политик безопасности |
| `make test-rate-limit` | Тест rate limiting |
| `make test-ct` | Тест CT-журнала |
| `make test-compromise` | Тест компрометации ключей |
| `make test-rsa-1024` | Тест блокировки RSA-1024 |
| `make test-detection-anomalies` | Тест детекции аномалий |

### Команды очистки

| Команда | Описание |
|---------|----------|
| `make clean-pki` | Очистить только PKI файлы |
| `make clean-logs` | Очистить только логи |
| `make clean-audit` | Очистить журналы аудита |
| `make clean-tests` | Очистить тестовые файлы (включая tests/pki) |
| `make clean-all` | Полная очистка всего |

## Участие в разработке

1. Форкните репозиторий
2. Создайте ветку (`git checkout -b feature/amazing-feature`)
3. Закоммитьте изменения (`git commit -m 'Add amazing feature'`)
4. Запушьте ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## Документация спринтов

- [Спринт 1](docs/sprints/sprint1.md) - Базовая структура и генерация ключей
- [Спринт 2](docs/sprints/sprint2.md) - Расширенные возможности CA
- [Спринт 3](docs/sprints/sprint3.md) - База данных и HTTP репозиторий
- [Спринт 4](docs/sprints/sprint4.md) - CRL (Certificate Revocation List)
- [Спринт 5](docs/sprints/sprint5.md) - OCSP (Online Certificate Status Protocol)
- [Спринт 6](docs/sprints/sprint6.md) - Клиентские инструменты и валидация
- [Спринт 7](docs/sprints/sprint7.md) - Аудит, политики, rate limiting, CT, компрометация