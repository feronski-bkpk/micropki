# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это профессиональный инструмент командной строки для создания и управления инфраструктурой публичных ключей (PKI) с поддержкой корневых и промежуточных центров сертификации, выпуска сертификатов различных типов, а также **хранения сертификатов в базе данных SQLite** и **HTTP репозитория** для обслуживания сертификатов по REST API.

## Содержание

- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Установка](#установка)
- [Использование](#использование)
  - [Команды CA](#команды-ca)
  - [Команды базы данных](#команды-базы-данных)
  - [Команды репозитория](#команды-репозитория)
- [Примеры](#примеры)
- [Структура проекта](#структура-проекта)
- [API Репозитория](#api-репозитория)
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

### **Безопасность**
- Использование только криптостойких алгоритмов
- Защита от padding oracle атак (AES-GCM)
- Безопасное затирание паролей в памяти
- Проверка соответствия ключа и сертификата
- Верификация самоподписанных сертификатов
- Валидация цепочек сертификатов согласно RFC 5280

### **Технические детали**
- Написано на Go (стандартная библиотека + `github.com/mattn/go-sqlite3`)
- SQLite для хранения сертификатов
- HTTP сервер на стандартном `net/http`
- Полное покрытие тестами
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

# 5. Создайте промежуточный CA (автоматически сохраняется в БД)
echo "MyIntermediatePass456" > intermediate-pass.txt
./micropki-cli ca issue-intermediate \
  --root-cert ./pki/root/certs/ca.cert.pem \
  --root-key ./pki/root/private/ca.key.pem \
  --root-pass-file root-pass.txt \
  --subject "/CN=Мой Промежуточный CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file intermediate-pass.txt \
  --out-dir ./pki/intermediate \
  --db-path ./pki/micropki.db

# 6. Выпустите серверный сертификат (автоматически сохраняется в БД)
./micropki-cli ca issue-cert \
  --ca-cert ./pki/intermediate/certs/intermediate.cert.pem \
  --ca-key ./pki/intermediate/private/intermediate.key.pem \
  --ca-pass-file intermediate-pass.txt \
  --template server \
  --subject "CN=example.com" \
  --san dns:example.com \
  --san dns:www.example.com \
  --out-dir ./pki/certs \
  --db-path ./pki/micropki.db

# 7. Посмотрите все сертификаты в БД
./micropki-cli ca list-certs --db-path ./pki/micropki.db

# 8. Запустите HTTP репозиторий
./micropki-cli repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db

# 9. В другом терминале получите сертификат через API
curl http://127.0.0.1:8080/ca/root
curl http://127.0.0.1:8080/certificate/<серийный-номер>
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

#### `ca issue-intermediate`
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
| `--db-path` | Путь к БД для автоматической вставки | - |

#### `ca issue-cert`
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
| `--db-path` | Путь к БД для автоматической вставки | - |

#### `ca list-certs`
Список всех сертификатов в базе данных.

```bash
./micropki-cli ca list-certs [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--db-path` | Путь к базе данных | `./pki/micropki.db` |
| `--status` | Фильтр по статусу: `valid`, `revoked`, `expired` | все |
| `--format` | Формат вывода: `table`, `json`, `csv` | `table` |

#### `ca show-cert <serial>`
Показать конкретный сертификат по серийному номеру.

```bash
./micropki-cli ca show-cert <serial> [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--db-path` | Путь к базе данных | `./pki/micropki.db` |
| `--format` | Формат вывода: `pem`, `text` | `pem` |

#### `ca verify`
Проверка сертификата.

```bash
./micropki-cli ca verify --cert ./pki/certs/cert.pem
```

#### `ca verify-chain`
Проверка полной цепочки сертификатов.

```bash
./micropki-cli ca verify-chain \
  --leaf ./pki/certs/leaf.cert.pem \
  --intermediate ./pki/intermediate/certs/intermediate.cert.pem \
  --root ./pki/root/certs/ca.cert.pem
```

### Команды базы данных

#### `db init`
Инициализация базы данных SQLite.

```bash
./micropki-cli db init [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--db-path` | Путь к файлу базы данных | `./pki/micropki.db` |
| `--force` | Принудительная перезапись | `false` |

### Команды репозитория

#### `repo serve`
Запуск HTTP сервера репозитория.

```bash
./micropki-cli repo serve [параметры]
```

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--host` | Адрес для прослушивания | `127.0.0.1` |
| `--port` | Порт | `8080` |
| `--db-path` | Путь к базе данных | `./pki/micropki.db` |
| `--cert-dir` | Директория с сертификатами CA | `./pki/certs` |
| `--log-file` | Файл для логов HTTP сервера | - |
| `--config` | Путь к конфигурационному файлу | - |

#### `repo status`
Проверка статуса сервера репозитория.

```bash
./micropki-cli repo status [--port 8080]
```

## Примеры

### Пример 1: Полный рабочий процесс с БД и репозиторием

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

# 3. Создание Intermediate CA (с сохранением в БД)
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

# 4. Выпуск нескольких сертификатов
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

# 5. Просмотр всех сертификатов
./micropki-cli ca list-certs --db-path ./pki/micropki.db --format table

# 6. Запуск репозитория
./micropki-cli repo serve --host 0.0.0.0 --port 8443 --db-path ./pki/micropki.db

# 7. В другом терминале получение сертификата через API
curl http://localhost:8443/ca/root
curl http://localhost:8443/certificate/$(./micropki-cli ca list-certs --db-path ./pki/micropki.db --format json | jq -r '.[0].serial_hex')
```

### Пример 2: Работа с JSON выводом

```bash
# Получить все сертификаты в JSON
./micropki-cli ca list-certs --db-path ./pki/micropki.db --format json | jq '.[] | {serial: .serial_hex, subject: .subject}'

# Фильтрация через jq
./micropki-cli ca list-certs --db-path ./pki/micropki.db --format json | jq '.[] | select(.status=="valid")'

# Подсчет сертификатов
./micropki-cli ca list-certs --db-path ./pki/micropki.db --format json | jq length
```

### Пример 3: Экспорт в CSV

```bash
# Экспорт всех сертификатов в CSV файл
./micropki-cli ca list-certs --db-path ./pki/micropki.db --format csv > certificates.csv

# Импорт в электронную таблицу или анализ
cat certificates.csv | column -t -s, | less
```

### Пример 4: Интеграция с мониторингом

```bash
# Проверка здоровья репозитория
if curl -s http://localhost:8080/health | grep -q "ok"; then
  echo "Репозиторий работает"
else
  echo "Репозиторий не отвечает"
fi

# Получение количества сертификатов
COUNT=$(./micropki-cli ca list-certs --db-path ./pki/micropki.db --format json | jq length)
echo "Всего сертификатов: $COUNT"
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
│       ├── config/                 # Конфигурация (YAML/JSON)
│       ├── crypto/                 # Криптография
│       ├── csr/                    # Обработка CSR
│       ├── database/               # SQLite база данных
│       ├── repository/             # HTTP репозиторий
│       ├── san/                    # Subject Alternative Names
│       ├── serial/                 # Генератор серийных номеров
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
├── micropki.db                       # База данных SQLite
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
    └── ...                           # Другие сертификаты
```

## API Репозитория

### Эндпоинты

| Метод | Путь | Описание | Коды ответа |
|-------|------|----------|-------------|
| GET | `/health` | Проверка работоспособности | 200, 503 |
| GET | `/certificate/<serial>` | Получение сертификата по серийному номеру | 200, 400, 404 |
| GET | `/ca/root` | Получение корневого CA сертификата | 200, 404 |
| GET | `/ca/intermediate` | Получение промежуточного CA сертификата | 200, 404 |
| GET | `/crl` | Заглушка для CRL (Sprint 4) | 501 |

### Примеры запросов

```bash
# Проверка здоровья
curl http://localhost:8080/health
{"status":"ok","database":"connected"}

# Получение корневого CA
curl http://localhost:8080/ca/root -o root.pem

# Получение сертификата по серийному номеру
curl http://localhost:8080/certificate/1d7a6df2dc963c57a6a57530251bd819c00d2d6a -o cert.pem

# Проверка CRL (заглушка)
curl -v http://localhost:8080/crl
< HTTP/1.1 501 Not Implemented
CRL generation not yet implemented (Sprint 4)
```

## Безопасность

### Криптографические стандарты

| Компонент | Технология | Обоснование |
|-----------|------------|-------------|
| **RSA ключи** | 2048/4096 бит | Промышленный стандарт |
| **ECC ключи** | P-256/P-384 (NIST) | Рекомендовано NSA |
| **Шифрование ключей CA** | AES-256-GCM | Аутентифицированное шифрование |
| **Ключи конечных субъектов** | Незашифрованные | Для совместимости |
| **Производные ключи** | PBKDF2, 600,000 итераций | OWASP рекомендации |
| **Серийные номера** | 64-бит composite + БД | Глобальная уникальность |

### Рекомендации по эксплуатации

1. **Регулярное резервное копирование** БД и директорий `private/`
2. **Мониторинг** через `/health` эндпоинт
3. **Ограничение доступа** к порту репозитория (8443) через firewall
4. **Аудит** через `ca list-certs` и логи HTTP сервера
5. **Тестирование уникальности** серийных номеров через `make test-serial-uniqueness`

## Тестирование

### Запуск тестов

```bash
# Модульные тесты
make test

# Тестирование базы данных
make test-db

# Тестирование репозитория
make test-repo

# Тестирование генератора серийных номеров
make test-serial

# Интеграционные тесты Спринта 3
make test-integration-sprint3

# Тест уникальности серийных номеров (100 сертификатов)
make test-serial-uniqueness

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
| `make test-coverage` | Запустить тесты с отчётом о покрытии |
| `make lint` | Проверить стиль кода |
| `make fmt` | Отформатировать код |
| `make vet` | Запустить статический анализ |

### Цели для работы с БД и репозиторием

| Команда | Описание |
|---------|----------|
| `make db-init` | Инициализация базы данных |
| `make list-certs` | Список всех сертификатов |
| `make show-cert SERIAL=<hex>` | Показать сертификат по серийному номеру |
| `make repo-serve` | Запуск HTTP сервера |
| `make repo-stop` | Остановка HTTP сервера |
| `make repo-status` | Проверка статуса сервера |
| `make test-api` | Тестирование API эндпоинтов |

### Цели для тестирования Спринта 3

| Команда | Описание |
|---------|----------|
| `make test-db` | Тестирование базы данных |
| `make test-repo` | Тестирование репозитория |
| `make test-serial` | Тестирование генератора серийных номеров |
| `make test-serial-uniqueness` | Тест уникальности 100 серийных номеров |
| `make test-integration-sprint3` | Полные интеграционные тесты |
| `make example-full` | Создание полной PKI иерархии с БД |

### Пример полного цикла разработки

```bash
# 1. Очистка и форматирование
make clean fmt

# 2. Сборка
make build

# 3. Инициализация БД
make db-init

# 4. Создание полной PKI иерархии
make example-full

# 5. Запуск репозитория
make repo-serve
# (в другом терминале)
make repo-status
make test-api

# 6. Тестирование
make test-serial-uniqueness
make test-integration-sprint3

# 7. Остановка
make repo-stop
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