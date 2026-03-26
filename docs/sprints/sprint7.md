## **Отчёт о выполнении Спринта 7 - MicroPKI (Go)**

### **Общая информация**

- **Язык реализации:** Go
- **Основные пакеты:** стандартная библиотека + `github.com/mattn/go-sqlite3`, `gopkg.in/yaml.v3`
- **Статус:** Все обязательные требования Спринта 7 выполнены

### **Структура проекта (дополнения Спринта 7)**

```
micropki/
├── micropki/                         # Основной пакет
│   ├── cmd/
│   │   └── micropki/                 # Точка входа CLI
│   │       └── main.go               # Добавлены команды audit, test, compromise
│   └── internal/                     # Внутренние пакеты
│       ├── audit/                    # НОВЫЙ: Система аудита
│       │   ├── audit.go              # NDJSON логгер, хеш-цепочка SHA-256
│       │   ├── verify.go             # Проверка целостности, блокировка операций
│       │   └── anomaly.go            # Детекция аномалий (эвристический анализ)
│       ├── policy/                   # НОВЫЙ: Политики безопасности
│       │   └── policy.go             # Проверка RSA/ECC размеров, сроков, SAN, wildcard
│       ├── ratelimit/                # НОВЫЙ: Rate limiting
│       │   └── limiter.go            # Token bucket алгоритм
│       ├── transparency/             # НОВЫЙ: Certificate Transparency
│       │   └── ct.go                 # CT-журнал (ct.log)
│       ├── compromise/               # НОВЫЙ: Компрометация ключей
│       │   └── compromise.go         # Таблица compromised_keys, блокировка
│       ├── config/                   # РАСШИРЕН: Конфигурация YAML/TOML
│       │   └── config.go             # Добавлены PolicyConfig, AuditConfig
│       ├── ca/                       # РАСШИРЕН: Логика CA
│       │   ├── ca.go                 # Добавлена проверка compromised keys
│       │   └── intermediate.go       # Интеграция политик, аудита, CT-журнала
│       ├── database/                 # РАСШИРЕН: База данных
│       │   └── db.go                 # Добавлена таблица compromised_keys
│       ├── repository/               # РАСШИРЕН: HTTP сервер
│       │   └── server.go             # Добавлен rate limiting
│       └── crl/                      # РАСШИРЕН: CRL
│           └── generator.go          # Исправлены пути к сертификатам
├── tests/                            # Интеграционные тесты
│   └── integration_test.go           # Обновлены тесты
├── scripts/                          # Скрипты тестирования
│   ├── test-sprint7.sh               # НОВЫЙ: Полный тест спринта 7
│   └── test-all.sh                   # Обновлен для включения спринта 7
├── Makefile                          # РАСШИРЕН: Добавлены цели спринта 7
├── go.mod                            # Добавлены зависимости (yaml, sqlite3)
└── README.md                         # ОБНОВЛЕН: Документация спринта 7
```

### **Что было реализовано в Спринте 7**

#### **1. Система аудита с криптографической целостностью**

- **Файл:** `micropki/internal/audit/audit.go`
- **Формат:** NDJSON (newline-delimited JSON)
- **Хеш-цепочка:**
  - SHA-256 хеш каждой записи
  - `prev_hash` — хеш предыдущей записи
  - Первая запись имеет `prev_hash = "0"*64`
  - Отдельный файл `chain.dat` для хранения последнего хеша
- **Ротация журнала:** по размеру (настраиваемый порог, количество бэкапов)
- **Обязательные события:**
  - Инициализация CA
  - Выпуск сертификата (started/success/failure)
  - Отзыв сертификата
  - Компрометация ключа
  - Нарушение политик
  - Генерация CRL
- **Команды CLI:**
  - `audit query` — поиск с фильтрацией (--from, --to, --level, --operation, --serial, --format, --verify)
  - `audit verify` — проверка целостности всей цепочки

#### **2. Принудительное применение политик безопасности**

- **Файл:** `micropki/internal/policy/policy.go`
- **Размеры ключей:**
  - RSA: Корневой CA ≥ 4096, Промежуточный ≥ 3072, Конечный ≥ 2048
  - ECC: Корневой/Промежуточный ≥ P-384, Конечный ≥ P-256
  - Блокировка RSA-1024 (проверено тестом)
- **Сроки действия:**
  - Корневой CA ≤ 10 лет (3650 дней)
  - Промежуточный CA ≤ 5 лет (1825 дней)
  - Конечные сертификаты ≤ 1 год (365 дней)
- **Ограничения SAN:**
  - Wildcard блокируется с ошибкой
  - Проверка разрешенных типов для каждого шаблона:
    - `server`: dns, ip (email, uri запрещены)
    - `client`: dns, email (ip, uri запрещены)
    - `code_signing`: dns, uri (ip, email запрещены)
- **Алгоритмы подписи:** SHA-1 и MD5 блокируются
- **Ограничение длины пути:** промежуточные CA имеют pathLen=0

#### **3. Rate limiting (ограничение скорости)**

- **Файл:** `micropki/internal/ratelimit/limiter.go`
- **Алгоритм:** Token bucket
- **Конфигурация:** флаги `--rate-limit` и `--rate-burst`
- **HTTP ответ:** 429 Too Many Requests с заголовком `Retry-After`
- **Применение:** ко всем эндпоинтам репозитория

#### **4. Certificate Transparency (CT) симуляция**

- **Файл:** `micropki/internal/transparency/ct.go`
- **Журнал:** `./pki/audit/ct.log`
- **Формат записи:** `timestamp serial subject fingerprint issuer`
- **Запись:** при каждом выпуске сертификата

#### **5. Компрометация ключей и блокировка**

- **Файл:** `micropki/internal/compromise/compromise.go`
- **Команда CLI:** `ca compromise --cert <path> --reason keyCompromise`
- **Таблица БД:** `compromised_keys`
  - `public_key_hash` — SHA-256 открытого ключа
  - `certificate_serial` — серийный номер
  - `compromise_date` — дата компрометации
  - `compromise_reason` — причина
- **Экстренный CRL:** генерация при компрометации
- **Блокировка:** проверка перед выпуском, отказ при обнаружении скомпрометированного ключа

#### **6. Детекция аномалий**

- **Файл:** `micropki/internal/audit/anomaly.go`
- **Команда CLI:** `audit detect-anomalies --window <часы>`
- **Обнаруживаемые аномалии:**
  - Всплеск активности (>20 запросов/мин)
  - Много ошибок (>5 ошибок выпуска)
  - Компрометации ключей
  - Высокий процент ошибок (>30%)

#### **7. Конфигурация YAML/TOML**

- **Файл:** `micropki/internal/config/config.go`
- **Поддержка:** YAML, JSON, TOML
- **Флаг CLI:** `--config <путь>`
- **Настраиваемые параметры:**
  - Политики безопасности (размеры ключей, сроки, SAN)
  - Аудит (пути, ротация)
  - Rate limiting
  - Сервер (хост, порт, директории)

### **Тестирование**

#### **Выполненные тесты**

| ID | Тест |
|----|------|
| TEST-51 | RSA-1024 блокировка |
| TEST-52 | Превышение срока >365 дней |
| TEST-53 | Wildcard SAN |
| TEST-54 | Email SAN для code_signing |
| TEST-55 | Обнаружение подделки audit.log |
| TEST-56 | Обнаружение удаленной записи |
| TEST-57 | Компрометация и блокировка |
| TEST-58 | Rate limiting (4x200, 1x429) |
| TEST-59 | CT-журнал |
| TEST-60 | Полный интеграционный тест |

#### **Автоматизированные тесты**

- Модульные тесты: `go test ./micropki/internal/...`
- Интеграционные тесты: `make test-sprint7`
- Тест детекции аномалий: `make test-detection-anomalies`
- Тест rate limiting: `make test-rate-limit`

### **Новые команды CLI (Спринт 7)**

```bash
# Аудит
micropki-cli audit query --from "2026-03-25T00:00:00Z" --operation issue --format table
micropki-cli audit verify --log-file ./pki/audit/audit.log
micropki-cli audit detect-anomalies --window 24

# Компрометация
micropki-cli ca compromise --cert ./pki/certs/test.cert.pem --reason keyCompromise

# Rate limiting
micropki-cli repo serve --host 127.0.0.1 --port 8080 --rate-limit 2 --rate-burst 3

# Тестирование
micropki-cli test rsa-1024
```

### **Новые файлы и директории**

```
pki/
├── audit/                           # Новая директория
│   ├── audit.log                    # NDJSON журнал с хеш-цепочкой
│   ├── chain.dat                    # Последний хеш
│   └── ct.log                       # CT-журнал
├── micropki.db                      # База данных (добавлена таблица compromised_keys)
└── crl/
    └── intermediate.crl.pem         # CRL (генерируется при компрометации)
```

### **Ключевые достижения**

1. **Криптографическая целостность аудита** — SHA-256 хеш-цепочка защищает от подделки
2. **Принудительное применение политик** — все нарушения блокируются и регистрируются
3. **Rate limiting** — защита от DDoS на уровне HTTP
4. **CT-журнал** — прозрачность выпуска сертификатов
5. **Компрометация ключей** — отслеживание и блокировка
6. **Детекция аномалий** — эвристический анализ угроз
7. **Гибкая конфигурация** — YAML/TOML файлы для всех параметров
8. **Полное тестовое покрытие** — 42 требования, 100% выполнение