# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это инструмент командной строки для создания и управления инфраструктурой публичных ключей (PKI) с поддержкой корневых и промежуточных центров сертификации, выпуска сертификатов различных типов, системой управления списками отзыва сертификатов (CRL), OCSP-ответчиком для проверки статуса сертификатов в реальном времени, а также полным набором клиентских инструментов для генерации CSR, запросов на выпуск сертификатов и проверки цепочек доверия.

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
  - [Команды CA](#команды-ca)
  - [Клиентские команды](#клиентские-команды)
  - [Команды управления CRL](#команды-управления-crl)
  - [Команды OCSP](#команды-ocsp)
  - [Команды базы данных](#команды-базы-данных)
  - [Команды репозитория](#команды-репозитория)
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
  - **OCSP Responder** - специальный сертификат для OCSP-ответчика
- **Поддержка Subject Alternative Names (SAN)**:
  - DNS имена
  - IP адреса
  - Email адреса
  - URI

### **Клиентские инструменты**
- **Генерация CSR** (`client gen-csr`):
  - Генерация закрытого ключа (RSA/ECC)
  - Создание PKCS#10 запроса с SAN
  - Сохранение ключа с правами 0600
- **Отправка CSR в репозиторий** (`client request-cert`):
  - HTTP API с поддержкой аутентификации
  - Выбор шаблона сертификата
  - Автоматическое сохранение полученного сертификата
- **Валидация цепочек сертификатов** (`client validate`):
  - Построение пути от конечного до доверенного корня
  - Проверка подписей, сроков действия, ограничений
  - Поддержка параметра `--validation-time` для тестирования
  - Вывод в форматах text/json
- **Проверка статуса отзыва** (`client check-status`):
  - Приоритет: OCSP → CRL
  - Автоматическое извлечение URL из AIA/CDP
  - Детальный вывод статуса с причиной и временем отзыва

### **Управление отзывом сертификатов (CRL)**
- **Полная поддержка CRL версии 2 (v2)** согласно RFC 5280
- **Отзыв сертификатов** с указанием причины (10 стандартных причин)
- **Генерация CRL** для корневого и промежуточных CA
- **Монотонные номера CRL** - автоматическое увеличение при каждой генерации
- **HTTP распространение CRL** с правильными заголовками кэширования (ETag, Last-Modified)

### **Проверка статуса в реальном времени (OCSP)**
- **Полная поддержка RFC 6960** (Online Certificate Status Protocol)
- **Специализированный OCSP responder сертификат** с расширением id-kp-OCSPSigning
- **Обработка OCSP-запросов** с извлечением CertID и nonce
- **Формирование подписанных ответов** со статусами:
  - `good` - сертификат действителен
  - `revoked` - сертификат отозван (с указанием причины и даты)
  - `unknown` - сертификат не найден или выпущен другим CA
- **Поддержка nonce** для защиты от повторного воспроизведения
- **Кэширование ответов** для повышения производительности
- **Детальное логирование** всех запросов

### **Репозиторий и база данных**
- **SQLite для хранения** всех выпущенных сертификатов
- **HTTP сервер репозитория** для распространения сертификатов и CRL
- **API эндпоинты**:
  - `/health` - проверка работоспособности
  - `/certificate/<serial>` - получение сертификата по серийному номеру
  - `/ca/root` и `/ca/intermediate` - получение CA сертификатов
  - `/crl` и `/crl/<filename>` - получение CRL
  - `/request-cert` - приём CSR и выпуск сертификатов (POST)

### **Безопасность**
- Использование только криптостойких алгоритмов
- Защита от padding oracle атак (AES-GCM)
- Безопасное затирание паролей в памяти
- Проверка соответствия ключа и сертификата
- Верификация самоподписанных сертификатов
- Валидация цепочек сертификатов согласно RFC 5280
- Права доступа 0600 для закрытых ключей

### **Технические детали**
- Написано на Go (стандартная библиотека + `github.com/mattn/go-sqlite3`)
- SQLite для хранения сертификатов и метаданных
- HTTP сервер на стандартном `net/http`
- Кросс-платформенная компиляция (Linux, macOS, Windows)
- OpenSSL совместимость
- Полный набор Makefile целей для разработки и тестирования

## Быстрый старт

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/feronski-bkpk/micropki
cd micropki

# 2. Соберите проект
make build

# 3. Создайте полную PKI иерархию (включая БД)
make example-full

# 4. Запустите репозиторий и OCSP responder
./scripts/run-all.sh

# 5. Сгенерируйте CSR для серверного сертификата
./micropki-cli client gen-csr \
  --subject "/CN=test.example.com/O=Test Org/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:test.example.com \
  --out-key test.key.pem \
  --out-csr test.csr.pem

# 6. Отправьте CSR в репозиторий и получите сертификат
./micropki-cli client request-cert \
  --csr test.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert test.cert.pem

# 7. Проверьте цепочку сертификатов
./micropki-cli client validate \
  --cert test.cert.pem \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem

# 8. Проверьте статус сертификата (OCSP → CRL)
./micropki-cli client check-status \
  --cert test.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem

# 9. Остановите сервисы
./scripts/stop-all.sh
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

**Опциональные параметры:**
- `--key-type` - тип ключа: `rsa` или `ecc` (по умолчанию: rsa)
- `--out-dir` - выходная директория (по умолчанию: ./pki)
- `--validity-days` - срок действия в днях (по умолчанию: 3650)
- `--log-file` - файл для логов
- `--force` - принудительная перезапись

#### `ca issue-intermediate`
Создание промежуточного CA.

```bash
./micropki-cli ca issue-intermediate [параметры]
```

**Обязательные параметры:**
- `--root-cert` - сертификат корневого CA
- `--root-key` - ключ корневого CA
- `--root-pass-file` - пароль корневого CA
- `--subject` - Distinguished Name для промежуточного CA
- `--key-type` - тип ключа
- `--key-size` - размер ключа
- `--passphrase-file` - пароль для промежуточного CA

#### `ca issue-cert`
Выпуск конечного сертификата.

```bash
./micropki-cli ca issue-cert [параметры]
```

**Обязательные параметры:**
- `--ca-cert` - сертификат промежуточного CA
- `--ca-key` - ключ промежуточного CA
- `--ca-pass-file` - пароль промежуточного CA
- `--template` - шаблон: `server`, `client`, `code_signing`

**Опциональные параметры:**
- `--csr` - подписать внешний CSR вместо генерации нового ключа
- `--subject` - различающееся имя (если не используется CSR)
- `--san` - альтернативные имена субъекта
- `--key-type` - тип ключа (если не используется CSR)
- `--key-size` - размер ключа (если не используется CSR)
- `--out-dir` - выходная директория
- `--validity-days` - срок действия
- `--db-path` - путь к базе данных

#### `ca issue-ocsp-cert`
Выпуск специального сертификата для OCSP-ответчика.

```bash
./micropki-cli ca issue-ocsp-cert [параметры]
```

**Обязательные параметры:**
- `--ca-cert` - сертификат промежуточного CA
- `--ca-key` - ключ промежуточного CA
- `--ca-pass-file` - пароль промежуточного CA
- `--subject` - Distinguished Name для OCSP-сертификата

**Опциональные параметры:**
- `--san` - альтернативные имена (dns:... или uri:...)
- `--key-type` - тип ключа (по умолчанию: rsa)
- `--key-size` - размер ключа (по умолчанию: 2048 для RSA, 256 для ECC)
- `--out-dir` - выходная директория (по умолчанию: ./pki/certs)
- `--validity-days` - срок действия (по умолчанию: 365)

#### `ca list-certs`
Список всех сертификатов в базе данных.

```bash
./micropki-cli ca list-certs [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--db-path` | Путь к базе данных | `./pki/micropki.db` |
| `--status` | Фильтр по статусу | все |
| `--format` | Формат вывода: `table`, `json`, `csv` | `table` |

### Клиентские команды

#### `client gen-csr`
Генерация закрытого ключа и запроса на подпись сертификата (CSR).

```bash
./micropki-cli client gen-csr [параметры]
```

**Параметры:**
| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--subject` | Distinguished Name (обязательно) | - |
| `--key-type` | Тип ключа: `rsa` или `ecc` | `rsa` |
| `--key-size` | Размер ключа (RSA: 2048/4096, ECC: 256/384) | 2048/256 |
| `--san` | Альтернативные имена (можно несколько) | - |
| `--out-key` | Выходной файл для ключа | `./key.pem` |
| `--out-csr` | Выходной файл для CSR | `./request.csr.pem` |

**Пример:**
```bash
./micropki-cli client gen-csr \
  --subject "/CN=server.example.com/O=MyOrg/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:server.example.com \
  --san ip:192.168.1.100 \
  --out-key server.key.pem \
  --out-csr server.csr.pem
```

#### `client request-cert`
Отправка CSR в репозиторий и получение подписанного сертификата.

```bash
./micropki-cli client request-cert [параметры]
```

**Параметры:**
| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--csr` | Путь к файлу CSR (PEM) | **обязательно** |
| `--template` | Шаблон: `server`, `client`, `code_signing` | **обязательно** |
| `--ca-url` | Базовый URL репозитория | **обязательно** |
| `--out-cert` | Выходной файл для сертификата | `./cert.pem` |
| `--api-key` | API ключ для аутентификации | - |
| `--timeout` | Таймаут HTTP запроса в секундах | `30` |

**Пример:**
```bash
./micropki-cli client request-cert \
  --csr server.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert server.cert.pem
```

#### `client validate`
Проверка цепочки сертификатов.

```bash
./micropki-cli client validate [параметры]
```

**Параметры:**
| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--cert` | Путь к конечному сертификату (PEM) | **обязательно** |
| `--untrusted` | Промежуточные сертификаты (можно несколько) | - |
| `--trusted` | Путь к доверенному корневому CA | `./pki/certs/ca.cert.pem` |
| `--crl` | Проверить CRL (файл или URL) | - |
| `--ocsp` | Выполнить OCSP проверку | `false` |
| `--mode` | Режим: `chain` (только подпись/срок) или `full` | `full` |
| `--format` | Формат вывода: `text` или `json` | `text` |
| `--validation-time` | Время проверки (RFC3339) | текущее |

**Пример:**
```bash
./micropki-cli client validate \
  --cert server.cert.pem \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem \
  --mode full \
  --format text
```

#### `client check-status`
Проверка статуса отзыва сертификата (OCSP → CRL).

```bash
./micropki-cli client check-status [параметры]
```

**Параметры:**
| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--cert` | Путь к сертификату (PEM) | **обязательно** |
| `--ca-cert` | Сертификат издателя (PEM) | **обязательно** |
| `--crl` | CRL файл или URL (опционально) | - |
| `--ocsp-url` | URL OCSP ответчика (опционально) | из AIA |
| `--format` | Формат вывода: `text` или `json` | `text` |

**Пример:**
```bash
./micropki-cli client check-status \
  --cert server.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem
```

### Команды управления CRL

#### `ca revoke <serial>`
Отзыв сертификата по серийному номеру.

```bash
./micropki-cli ca revoke <serial> [--reason <причина>] [--db-path <путь>]
```

**Поддерживаемые причины отзыва:**
- `unspecified` (0) - не указана
- `keyCompromise` (1) - компрометация ключа
- `cACompromise` (2) - компрометация CA
- `affiliationChanged` (3) - изменение принадлежности
- `superseded` (4) - замещён
- `cessationOfOperation` (5) - прекращение деятельности
- `certificateHold` (6) - временная приостановка
- `removeFromCRL` (8) - удаление из CRL
- `privilegeWithdrawn` (9) - отзыв привилегий
- `aACompromise` (10) - компрометация AA

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

**Параметры:**
| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--host` | Адрес для прослушивания | `127.0.0.1` |
| `--port` | Порт | `8081` |
| `--db-path` | Путь к базе данных | `./pki/micropki.db` |
| `--responder-cert` | Сертификат OCSP-ответчика (PEM) | **обязательно** |
| `--responder-key` | Ключ OCSP-ответчика (PEM, незашифрованный) | **обязательно** |
| `--ca-cert` | Сертификат издателя (PEM) | **обязательно** |
| `--cache-ttl` | Время жизни кэша в секундах | `60` |
| `--log-file` | Файл для логов | stderr |

### Команды базы данных

#### `db init`
Инициализация базы данных SQLite.

```bash
./micropki-cli db init --db-path ./pki/micropki.db
```

### Команды репозитория

#### `repo serve`
Запуск HTTP сервера репозитория.

```bash
./micropki-cli repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db
```

## Примеры

### Пример 1: Полный рабочий процесс с CSR и валидацией

```bash
# 1. Генерация CSR для серверного сертификата
./micropki-cli client gen-csr \
  --subject "/CN=app.example.com/O=My Company/C=RU" \
  --key-type rsa \
  --key-size 2048 \
  --san dns:app.example.com \
  --san dns:api.example.com \
  --out-key app.key.pem \
  --out-csr app.csr.pem

# 2. Отправка CSR в репозиторий
./micropki-cli client request-cert \
  --csr app.csr.pem \
  --template server \
  --ca-url http://localhost:8080 \
  --out-cert app.cert.pem

# 3. Проверка цепочки сертификатов
./micropki-cli client validate \
  --cert app.cert.pem \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem

# 4. Проверка статуса отзыва
./micropki-cli client check-status \
  --cert app.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem
```

### Пример 2: Отзыв сертификата и проверка через CRL

```bash
# 1. Отзыв сертификата
./micropki-cli ca revoke $(openssl x509 -in app.cert.pem -noout -serial | cut -d= -f2) \
  --reason keyCompromise \
  --db-path ./pki/micropki.db

# 2. Генерация обновлённого CRL
./micropki-cli ca gen-crl --ca intermediate --next-update 7

# 3. Проверка статуса (будет использовать CRL, так как OCSP может быть недоступен)
./micropki-cli client check-status \
  --cert app.cert.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem
```

### Пример 3: Работа с разными шаблонами и типами ключей

```bash
# Клиентский сертификат с ECC-256
./micropki-cli client gen-csr \
  --subject "/CN=client.example.com/O=My Company/C=RU" \
  --key-type ecc \
  --key-size 256 \
  --san email:user@example.com \
  --out-key client.key.pem \
  --out-csr client.csr.pem

./micropki-cli client request-cert \
  --csr client.csr.pem \
  --template client \
  --ca-url http://localhost:8080 \
  --out-cert client.cert.pem

# Сертификат подписи кода с RSA-4096
./micropki-cli client gen-csr \
  --subject "/CN=Code Signer/O=My Company/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --out-key signer.key.pem \
  --out-csr signer.csr.pem

./micropki-cli client request-cert \
  --csr signer.csr.pem \
  --template code_signing \
  --ca-url http://localhost:8080 \
  --out-cert signer.cert.pem
```

### Пример 4: Тестирование с параметром --validation-time

```bash
# Проверка сертификата в прошлом (должна быть ошибка срока действия)
./micropki-cli client validate \
  --cert app.cert.pem \
  --untrusted ./pki/intermediate/certs/intermediate.cert.pem \
  --trusted ./pki/root/certs/ca.cert.pem \
  --validation-time "2025-01-01T00:00:00Z"
```

## Структура проекта

```
micropki/
├── micropki/                         # Основной пакет
│   ├── cmd/
│   │   └── micropki/                 # Точка входа CLI
│   │       └── main.go
│   └── internal/                     # Внутренние пакеты
│       ├── ca/                       # Логика CA
│       ├── certs/                    # X.509 операции
│       ├── chain/                    # Проверка цепочек
│       ├── cli/                      # Клиентские команды
│       ├── config/                   # Конфигурация
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
    ├── test.example.com.cert.pem     # Тестовый сертификат
    ├── test.example.com.key.pem      # Незашифрованный ключ (0600)
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
| GET | `/crl` | Получение CRL (intermediate по умолчанию) |
| GET | `/crl?ca=root` | Получение корневого CRL |
| GET | `/crl/intermediate.crl` | CRL по имени файла |
| POST | `/request-cert?template=<template>` | Отправка CSR и получение сертификата |

### Примеры запросов

```bash
# Получение корневого CA
curl http://localhost:8080/ca/root -o root.cert.pem

# Получение сертификата по серийному номеру
curl http://localhost:8080/certificate/1234567890abcdef -o cert.pem

# Получение CRL
curl http://localhost:8080/crl -o intermediate.crl.pem

# Отправка CSR
curl -X POST -H "Content-Type: application/x-pem-file" \
  --data-binary @request.csr.pem \
  http://localhost:8080/request-cert?template=server \
  -o certificate.pem
```

## OCSP Responder API

### Эндпоинт

| Метод | Путь | Content-Type | Описание |
|-------|------|--------------|----------|
| POST | `/` | `application/ocsp-request` | OCSP запрос |

### Пример запроса

```bash
# Создание OCSP-запроса
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/test.example.com.cert.pem \
  -reqout ./request.der -noverify

# Отправка запроса
curl -X POST -H "Content-Type: application/ocsp-request" \
  --data-binary @request.der \
  http://127.0.0.1:8081 -o response.der

# Просмотр ответа
openssl ocsp -respin response.der -text -noverify
```

### Заголовки ответа

```
HTTP/1.1 200 OK
Content-Type: application/ocsp-response
Cache-Control: max-age=60, public
```

## Безопасность

### Криптографические стандарты

| Компонент | Технология |
|-----------|------------|
| **RSA ключи** | 2048/4096 бит |
| **ECC ключи** | P-256/P-384 |
| **Шифрование ключей CA** | AES-256-GCM |
| **Ключи OCSP responder** | Незашифрованные (0600) |
| **Производные ключи** | PBKDF2, 600,000 итераций |
| **Серийные номера** | 160 бит энтропии |
| **Права доступа к ключам** | 0600 (только владелец) |

### Меры безопасности

1. **Nonce защита** - предотвращение повторного воспроизведения в OCSP
2. **Подписанные ответы** - каждый ответ подписан ключом OCSP responder
3. **Валидация цепочек** - полная проверка согласно RFC 5280
4. **Кэширование с TTL** - ограничение времени жизни ответов
5. **Детальное логирование** - аудит всех запросов
6. **Защита ключей** - шифрование ключей CA, незашифрованные ключи только для OCSP
7. **Безопасное затирание** - пароли удаляются из памяти после использования

## Тестирование

### Запуск тестов

```bash
# Модульные тесты
make test

# Интеграционные тесты
make test-integration

# Тесты конкретных спринтов
make test-sprint2
make test-sprint3
make test-sprint4
make test-sprint5
make test-sprint6

# Все тесты (Go-тесты)
make test-all

# С покрытием
make test-coverage
```

## Makefile команды

### Основные цели

| Команда | Описание |
|---------|----------|
| `make build` | Собрать бинарный файл |
| `make clean` | Удалить все сгенерированные файлы |
| `make test` | Запустить модульные тесты |
| `make test-all` | Все Go-тесты (модульные + интеграционные) |
| `make example-full` | Создать полную PKI иерархию |

### Цели для работы с клиентом

| Команда | Описание |
|---------|----------|
| `make test-sprint6` | Запуск тестов спринта 6 |
| `make test-client-gen-csr` | Тест генерации CSR |
| `make test-client-request` | Тест запроса сертификата |
| `make test-client-validate` | Тест валидации цепочки |
| `make test-client-check-status` | Тест проверки отзыва |

### Цели для работы с OCSP

| Команда | Описание |
|---------|----------|
| `make ocsp-serve` | Запуск OCSP сервера |
| `make ocsp-test` | Тест действительного сертификата |
| `make test-ocsp` | Модульные тесты OCSP |
| `make test-ocsp-integration` | Интеграционные тесты OCSP |
| `make test-sprint5` | Тесты спринта 5 |

### Цели для работы с CRL

| Команда | Описание |
|---------|----------|
| `make crl-revoke` | Отзыв сертификата |
| `make crl-gen` | Генерация Intermediate CRL |
| `make crl-check` | Проверка статуса сертификата |
| `make test-crl-lifecycle` | Тест жизненного цикла CRL |

### Цели для работы с репозиторием

| Команда | Описание |
|---------|----------|
| `make repo-serve` | Запуск HTTP сервера |
| `make repo-stop` | Остановка HTTP сервера |
| `make repo-status` | Проверка статуса сервера |
| `make db-init` | Инициализация базы данных |
| `make list-certs` | Список всех сертификатов |

### Скрипты для управления сервисами

```bash
# Запуск всех сервисов (репозиторий + OCSP)
./scripts/run-all.sh

# Остановка всех сервисов
./scripts/stop-all.sh

# Настройка PKI с нуля
./scripts/setup-pki.sh

# Полное тестирование
./scripts/test-all.sh

# Тестирование спринта 6
./scripts/test-sprint6.sh
```

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