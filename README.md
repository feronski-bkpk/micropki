# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это инструмент командной строки для создания и управления инфраструктурой публичных ключей (PKI) с поддержкой корневых и промежуточных центров сертификации, выпуска сертификатов различных типов, системой управления списками отзыва сертификатов (CRL) и OCSP-ответчиком для проверки статуса сертификатов в реальном времени.

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
  - [Команды CA](#команды-ca)
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

### **Управление отзывом сертификатов (CRL)**
- **Полная поддержка CRL версии 2 (v2)** согласно RFC 5280
- **Отзыв сертификатов** с указанием причины (10 стандартных причин)
- **Генерация CRL** для корневого и промежуточных CA
- **Монотонные номера CRL** - автоматическое увеличение при каждой генерации
- **HTTP распространение CRL** с правильными заголовками кэширования

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

### **Безопасность**
- Использование только криптостойких алгоритмов
- Защита от padding oracle атак (AES-GCM)
- Безопасное затирание паролей в памяти
- Проверка соответствия ключа и сертификата
- Верификация самоподписанных сертификатов
- Валидация цепочек сертификатов согласно RFC 5280

### **Технические детали**
- Написано на Go (стандартная библиотека + `github.com/mattn/go-sqlite3`)
- SQLite для хранения сертификатов и метаданных
- HTTP сервер на стандартном `net/http`
- Кросс-платформенная компиляция (Linux, macOS, Windows)
- OpenSSL совместимость

## Быстрый старт

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/feronski-bkpk/micropki
cd micropki

# 2. Соберите проект
make build

# 3. Инициализируйте базу данных
./micropki-cli db init --db-path ./pki/micropki.db

# 4. Создайте корневой CA
echo "MyRootPass123" > root-pass.txt
./micropki-cli ca init \
  --subject "/CN=Мой Корневой CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file root-pass.txt \
  --out-dir ./pki/root \
  --validity-days 3650

# 5. Создайте промежуточный CA
echo "MyIntermediatePass456" > int-pass.txt
./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file root-pass.txt \
  --subject "/CN=Мой Промежуточный CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file int-pass.txt \
  --out-dir ./pki/intermediate \
  --db-path ./pki/micropki.db

# 6. Выпустите OCSP responder сертификат
./micropki-cli ca issue-ocsp-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file int-pass.txt \
  --subject "/CN=OCSP Responder/O=Моя Организация/C=RU" \
  --san dns:localhost \
  --out-dir ./pki/certs

# 7. Выпустите тестовый сертификат
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file int-pass.txt \
  --template server \
  --subject "CN=test.example.com" \
  --san dns:test.example.com \
  --out-dir ./pki/certs \
  --db-path ./pki/micropki.db

# 8. Запустите OCSP-ответчик
./micropki-cli ocsp serve \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path ./pki/micropki.db \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem

# 9. В другом терминале проверьте статус сертификата
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/test.example.com.cert.pem \
  -url http://127.0.0.1:8081 \
  -resp_text -noverify
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

**Пример:**
```bash
./micropki-cli ocsp serve \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path ./pki/micropki.db \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --cache-ttl 120 \
  --log-file ./logs/ocsp.log
```

### Команды базы данных

#### `db init`
Инициализация базы данных SQLite.

```bash
./micropki-cli db init --db-path ./pki/micropki.db
```

### Команды репозитория

#### `repo serve`
Запуск HTTP сервера репозитория (обслуживает сертификаты и CRL).

```bash
./micropki-cli repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db
```

## Примеры

### Пример 1: Полный рабочий процесс с CRL и OCSP

```bash
# 1. Инициализация БД
./micropki-cli db init --db-path ./pki/micropki.db

# 2. Создание Root CA
echo "rootpass" > root-pass.txt
./micropki-cli ca init \
  --subject "/CN=Production Root CA/O=My Company/C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file root-pass.txt \
  --out-dir ./pki/root

# 3. Создание Intermediate CA
echo "intpass" > int-pass.txt
./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file root-pass.txt \
  --subject "/CN=Production Intermediate CA/O=My Company/C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file int-pass.txt \
  --out-dir ./pki/intermediate \
  --db-path ./pki/micropki.db

# 4. Выпуск OCSP responder сертификата
./micropki-cli ca issue-ocsp-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file int-pass.txt \
  --subject "/CN=OCSP Responder/O=My Company/C=US" \
  --san dns:localhost \
  --out-dir ./pki/certs

# 5. Выпуск тестовых сертификатов
for i in {1..5}; do
  ./micropki-cli ca issue-cert \
    --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
    --ca-key ./pki/intermediate/private/intermediate.key.pem \
    --ca-pass-file int-pass.txt \
    --template server \
    --subject "CN=server$i.example.com" \
    --san dns:server$i.example.com \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db
done

# 6. Запуск OCSP-ответчика (в отдельном терминале)
./micropki-cli ocsp serve \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path ./pki/micropki.db \
  --responder-cert ./pki/certs/ocsp.cert.pem \
  --responder-key ./pki/certs/ocsp.key.pem \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem

# 7. Проверка статуса через OCSP
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.example.com.cert.pem \
  -url http://127.0.0.1:8081 \
  -resp_text -noverify

# 8. Отзыв сертификата
./micropki-cli ca revoke <серийный-номер> --reason keyCompromise

# 9. Повторная проверка статуса (должен быть revoked)
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.example.com.cert.pem \
  -url http://127.0.0.1:8081 \
  -resp_text -noverify

# 10. Генерация CRL
./micropki-cli ca gen-crl --ca intermediate --next-update 7

# 11. Запуск репозитория
./micropki-cli repo serve --host 0.0.0.0 --port 8080 --db-path ./pki/micropki.db
```

### Пример 2: Тестирование OCSP с nonce

```bash
# Запрос с nonce
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.example.com.cert.pem \
  -url http://127.0.0.1:8081 \
  -nonce -resp_text -noverify

# Запрос без nonce
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.example.com.cert.pem \
  -url http://127.0.0.1:8081 \
  -resp_text -noverify
```

### Пример 3: Прямые HTTP запросы к OCSP

```bash
# Создание OCSP-запроса в DER
openssl ocsp -issuer ./pki/intermediate/certs/intermediate.cert.pem \
  -cert ./pki/certs/server1.example.com.cert.pem \
  -reqout ./request.der -noverify

# Отправка через curl
curl -X POST -H "Content-Type: application/ocsp-request" \
  --data-binary @./request.der \
  http://127.0.0.1:8081 -o response.der

# Просмотр ответа
openssl ocsp -respin response.der -text -noverify
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
│       ├── config/                   # Конфигурация
│       ├── crl/                      # CRL генерация
│       ├── crypto/                   # Криптография
│       ├── csr/                      # Обработка CSR
│       ├── database/                 # SQLite база данных
│       ├── ocsp/                     # OCSP функциональность
│       ├── repository/               # HTTP репозиторий
│       ├── san/                      # Subject Alternative Names
│       ├── serial/                   # Генератор серийных номеров
│       └── templates/                # Шаблоны сертификатов
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
├── ocsp/                             # Кэш OCSP (опционально)
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
| GET | `/crl` | Получение CRL |
| GET | `/crl/<filename>` | CRL по имени файла |

## OCSP Responder API

### Эндпоинт

| Метод | Путь | Content-Type | Описание |
|-------|------|--------------|----------|
| POST | `/` (или `/ocsp` при интеграции) | `application/ocsp-request` | OCSP запрос |

### Пример запроса

```bash
curl -X POST -H "Content-Type: application/ocsp-request" \
  --data-binary @request.der \
  http://127.0.0.1:8081 -o response.der
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

### Меры безопасности OCSP

1. **Nonce защита** - предотвращение повторного воспроизведения
2. **Подписанные ответы** - каждый ответ подписан ключом OCSP responder
3. **Валидация издателя** - проверка соответствия CertID
4. **Кэширование с TTL** - ограничение времени жизни ответов
5. **Детальное логирование** - аудит всех запросов

## Тестирование

### Запуск тестов

```bash
# Все тесты
make test

# Тестирование OCSP
make test-ocsp
make test-ocsp-integration
make test-ocsp-all

# Тестирование CRL
make test-crl-lifecycle
make test-crl-unit

# Тестирование спринта 5
make test-sprint5

# Все тесты (спринты 1-5)
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
| `make test-all` | Все тесты (спринты 1-5) |

### Цели для работы с OCSP

| Команда | Описание |
|---------|----------|
| `make ocsp-serve` | Запуск OCSP сервера |
| `make ocsp-test` | Тест действительного сертификата |
| `make ocsp-test-revoked` | Тест отозванного сертификата |
| `make ocsp-test-unknown` | Тест неизвестного сертификата |
| `make ocsp-test-script` | Автоматическое тестирование OCSP |
| `make test-ocsp` | Модульные тесты OCSP |
| `make test-ocsp-integration` | Интеграционные тесты OCSP |
| `make test-sprint5` | Тесты спринта 5 |

### Цели для работы с CRL

| Команда | Описание |
|---------|----------|
| `make crl-revoke` | Интерактивный отзыв сертификата |
| `make crl-gen` | Генерация Intermediate CRL |
| `make crl-check` | Проверка статуса сертификата |
| `make crl-verify` | Просмотр CRL через OpenSSL |

### Цели для работы с БД и репозиторием

| Команда | Описание |
|---------|----------|
| `make db-init` | Инициализация базы данных |
| `make list-certs` | Список всех сертификатов |
| `make repo-serve` | Запуск HTTP сервера |
| `make repo-status` | Проверка статуса сервера |

### Пример полного цикла разработки

```bash
# 1. Очистка и форматирование
make clean fmt

# 2. Сборка
make build

# 3. Создание полной PKI иерархии
make example-full

# 4. Тестирование OCSP
make test-ocsp

# 5. Запуск OCSP сервера
make ocsp-serve
# (в другом терминале)
make ocsp-test

# 6. Остановка
make clean
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