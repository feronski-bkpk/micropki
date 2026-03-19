# Отчет о выполнении Спринта 6

## Общая информация
**Проект:** MicroPKI  
**Спринт:** 6  
**Цель:** Реализация механизма проверки путей сертификатов и клиентских инструментов для генерации CSR, запросов на выпуск сертификатов, полной проверки цепочек и контроля статуса отзыва (CRL + OCSP) с интеллектуальной логикой перехода (fallback).

## 1. Новые файлы (добавлено)

### `internal/validation/validator.go`
Пакет для валидации цепочек сертификатов согласно RFC 5280:
- `ValidationResult` - структурированный результат проверки
- `CertificateValidation` - результат проверки одного сертификата
- `ValidatorConfig` - конфигурация валидатора (время проверки, максимальная глубина)
- `PathValidator` - основной валидатор
- `NewPathValidator()` - создание валидатора с доверенными корнями
- `Validate()` - полная проверка цепочки:
  - Проверка каждого сертификата
  - Сбор ошибок и результатов
  - Формирование общего статуса

### `internal/validation/chain.go`
Пакет для построения цепочек сертификатов:
- `ChainBuilder` - построитель цепочек
- `NewChainBuilder()` - создание построителя с промежуточными сертификатами
- `BuildPath()` - построение пути от конечного сертификата до доверенного корня
- `buildPathRecursive()` - рекурсивный поиск издателя
- `isIssuerOf()` - проверка, является ли сертификат издателем другого

### `internal/validation/checks.go`
Пакет с базовыми проверками сертификатов:
- `PerformBasicChecks()` - выполнение базовых проверок:
  - Действительность подписи
  - Срок действия
  - Basic Constraints для CA
  - Key Usage
  - Path Length Constraints
- Поддержка параметра `validation-time` для тестирования

### `internal/revocation/checker.go`
Пакет с логикой проверки отзыва и fallback:
- `RevocationStatus` - enum статусов (Good, Revoked, Unknown)
- `RevocationResult` - результат проверки отзыва
- `RevocationChecker` - основной проверяльщик
- `RevocationCheckerConfig` - конфигурация (HTTP клиент, таймауты, кэш)
- `NewRevocationChecker()` - создание проверяльщика
- `CheckRevocation()` - проверка с приоритетом OCSP → CRL:
  1. Попытка OCSP если доступен URL
  2. Если OCSP не удался или статус unknown → переход на CRL
  3. Если CRL успешен → использование результата
  4. Если оба метода не удались → статус unknown

### `internal/revocation/ocsp_checker.go`
Пакет для OCSP-проверки:
- ASN.1 структуры для OCSP запросов/ответов
- `OCSPChecker` - проверяльщик через OCSP
- `NewOCSPChecker()` - создание OCSP-проверяльщика
- `Check()` - выполнение OCSP-проверки:
  - Извлечение OCSP URL из AIA
  - Создание OCSP запроса с хешами SHA-1
  - Отправка POST запроса с Content-Type: application/ocsp-request
  - Парсинг ответа и извлечение статуса
  - Кэширование результатов
- `buildOCSPRequest()` - построение запроса
- `parseOCSPResponse()` - разбор ответа
- `mapOCSPReason()` - преобразование кода причины в строку

### `internal/revocation/crl_checker.go`
Пакет для CRL-проверки:
- `CRLChecker` - проверяльщик через CRL
- `CRLCacheEntry` - запись в кэше CRL
- `NewCRLChecker()` - создание CRL-проверяльщика
- `Check()` - выполнение CRL-проверки:
  - Извлечение CRL URL из CDP
  - Загрузка CRL (HTTP или файл)
  - Проверка подписи CRL
  - Проверка срока действия (nextUpdate)
  - Поиск серийного номера в списке отозванных
  - Кэширование CRL
- `fetchCRL()` - загрузка CRL из URL или файла
- `parseCRL()` - парсинг PEM/DER CRL
- поддержка `allowExpired` и `maxCRLSize`

### `internal/revocation/aia_parser.go`
Пакет для извлечения OCSP URL из расширения Authority Information Access:
- `AIAParser` - парсер AIA
- `ParseAIA()` - извлечение OCSP URL из сертификата
- `HasOCSPResponder()` - проверка наличия OCSP URL

### `internal/revocation/cdp_parser.go`
Пакет для извлечения CRL URL из расширения CRL Distribution Points:
- `CDPParser` - парсер CDP
- `ParseCDP()` - извлечение URL точек распространения CRL
- `HasCRLDistributionPoint()` - проверка наличия CDP

### `internal/csr/generator.go`
Пакет для генерации CSR:
- `GenerateConfig` - конфигурация для генерации ключа и CSR
- `GenerateKeyAndCSR()` - генерация новой ключевой пары и CSR:
  - Генерация RSA/ECC ключа
  - Создание CSR с SAN (DNS, IP, email, URI)
  - Сохранение незашифрованного ключа с правами 0600
  - Сохранение CSR с правами 0644
  - Предупреждение о незашифрованном ключе
- `savePrivateKey()` - сохранение ключа в PKCS#8 PEM
- `saveCSR()` - сохранение CSR в PEM
- Вспомогательные функции для извлечения SAN

### `internal/cli/client.go`
Точка входа для клиентских команд:
- `RunClient()` - диспетчер подкоманд
- `printClientUsage()` - справка по клиентским командам

### `internal/cli/client_gen_csr.go`
Команда `client gen-csr`:
- Парсинг аргументов: `--subject`, `--key-type`, `--key-size`, `--san`, `--out-key`, `--out-csr`
- Валидация типов и размеров ключей (RSA: 2048/4096, ECC: 256/384)
- Парсинг DN и SAN
- Генерация ключа и CSR через `csr.GenerateKeyAndCSR()`
- Проверка прав доступа 0600 для ключа
- Вывод предупреждения о незашифрованном ключе

### `internal/cli/client_request_cert.go`
Команда `client request-cert` (CLI-26):
- Парсинг аргументов: `--csr`, `--template`, `--ca-url`, `--out-cert`, `--api-key`, `--timeout`
- Чтение и проверка CSR (PEM)
- HTTP POST запрос к `/request-cert?template=...`
- Заголовки: `Content-Type: application/x-pem-file`, `X-API-Key` (опционально)
- Обработка HTTP ошибок
- Сохранение полученного сертификата
- Вывод информации о сертификате (серийный номер, срок действия)

### `internal/cli/client_validate.go`
Команда `client validate` (CLI-27):
- Парсинг аргументов: `--cert`, `--untrusted`, `--trusted`, `--crl`, `--ocsp`, `--mode`, `--format`, `--validation-time`
- Загрузка сертификатов (конечный, промежуточные, доверенные корни)
- Построение цепочки через `ChainBuilder`
- Валидация через `PathValidator`
- Поддержка `--validation-time` для тестирования
- Вывод в форматах text/json
- Детальный результат с перечислением шагов проверки

### `internal/cli/client_check_status.go`
Команда `client check-status` (CLI-28):
- Парсинг аргументов: `--cert`, `--ca-cert`, `--crl`, `--ocsp-url`, `--format`
- Загрузка сертификатов
- Создание `RevocationChecker`
- Проверка статуса с fallback логикой (OCSP → CRL)
- Вывод статуса: good/revoked/unknown
- Детали: время и причина отзыва (если revoked)

### `internal/cli/client_utils.go`
Вспомогательные функции для клиента:
- `getDNSNames()`, `getIPAddresses()`, `getEmailAddresses()`, `getURIs()` - извлечение SAN
- `sanitizeFilename()` - безопасное имя файла
- `arrayFlags` - тип для многократного указания флагов (--san)

### `scripts/test-sprint6.sh`
Интеграционный тест-скрипт для проверки всех требований Спринта 6:
- Проверка доступности сервисов (репозиторий, OCSP)
- CLI-25: генерация CSR с RSA/ECC и SAN
- CLI-29: подписание CSR через CA (флаг `--csr`)
- CLI-26: отправка CSR в репозиторий через HTTP API
- CLI-27: валидация цепочки сертификатов
- VAL-1/2: проверка с параметром `--validation-time`
- REV-1/2/3: проверка отзыва с fallback (OCSP → CRL)
- LOG-16: проверка логирования API запросов
- Тестирование разных шаблонов (server, client, code_signing)
- Тестирование разных типов ключей (RSA, ECC)

### `scripts/test-revocation.sh`
Скрипт для тестирования проверки отзыва:
- Генерация тестового сертификата
- Проверка статуса GOOD
- Отзыв сертификата
- Генерация CRL
- Повторная проверка статуса REVOKED

## 2. Измененные файлы (модифицировано)

### `internal/ca/ca.go`
**Добавлены:**
- `IssueCertificateFromCSR()` - выпуск сертификата на основе внешнего CSR:
  - Загрузка CA сертификата и ключа
  - Парсинг и проверка CSR через `csr.ParseAndVerifyCSR()`
  - Проверка, что CSR не запрашивает права CA
  - Извлечение SAN через `csr.GetSANsFromCSR()`
  - Валидация совместимости с шаблоном через `csr.ValidateCSRForTemplate()`
  - Генерация серийного номера
  - Создание шаблона согласно типу (server/client/code_signing)
  - Подписание сертификата
  - Сохранение и вставка в БД

### `internal/ca/intermediate.go`
**Изменены:**
- `processExternalCSR()` - расширена для обработки CSR:
  - Чтение файла CSR
  - Парсинг и проверка подписи
  - Извлечение субъекта, SAN и публичного ключа
  - Проверка на запрос CA прав
  - Валидация совместимости с шаблоном
  - Добавлена отладка для диагностики

### `internal/csr/csr.go`
**Изменены:**
- `ValidateCSRForTemplate()` - исправлена логика проверки для серверных сертификатов
- `GetSANsFromCSR()` - улучшено извлечение SAN из расширений
- Добавлена поддержка ASN.1 парсинга для SAN

### `internal/database/db.go`
**Добавлены:**
- `GetCertificateStatus()` - получение статуса по серийному номеру (для OCSP)
- `DatabaseStatusChecker` - реализация интерфейса `StatusChecker`
- `mapRevocationReason()` - преобразование строки причины в код
- Поле `logger` в структуре `DB` для отладки

**Изменены:**
- `New()` - добавлена инициализация логгера

### `internal/ocsp/responder.go`
**Изменены:**
- `handleRequest()` - улучшена обработка отозванных сертификатов:
  - Проверка статуса в БД при каждом запросе
  - Инвалидация кэша для отозванных сертификатов
  - Возврат правильного статуса revoked
- `ResponderConfig` - изменён тип `ResponderKey` на `crypto.Signer`

### `internal/ocsp/cache.go`
**Добавлены:**
- `InvalidateBySerial()` - удаление из кэша по серийному номеру
- `Clear()` - полная очистка кэша

### `internal/ocsp/ocsp_test.go`
**Изменены:**
- Обновлены тесты под новый интерфейс `StatusChecker`
- Добавлен `MockDB` с правильной реализацией
- Исправлены ASN.1 структуры для тестов

### `internal/templates/templates.go`
**Изменены:**
- Добавлены функции `AddOCSPAIA()` и `AddCRLCDP()` для добавления расширений
- `GetDefaultOCSPURL()` и `GetDefaultCRLURL()` - URL по умолчанию
- Шаблоны теперь включают AIA и CDP расширения

### `internal/repository/server.go`
**Добавлены:**
- `handleRequestCert()` - обработчик POST /request-cert:
  - Проверка метода и Content-Type
  - Чтение CSR из тела запроса
  - Получение шаблона из query параметра
  - Проверка API ключа (X-API-Key)
  - Вызов `ca.IssueCertificateFromCSR()`
  - Логирование запросов (API REQUEST/SUCCESS/ERROR)
  - Возврат сертификата с Content-Type: application/x-pem-file
  - Заголовок X-Serial-Number

**Изменены:**
- `Start()` - добавлен маршрут `/request-cert`
- `serveCRLFile()` - добавлен ETag для кэширования

### `micropki/cmd/micropki/main.go`
**Добавлены новые подкоманды:**
- `client` - группа клиентских команд:
  - `gen-csr` - генерация CSR
  - `request-cert` - отправка CSR в репозиторий
  - `validate` - валидация цепочки
  - `check-status` - проверка статуса отзыва

**Изменены:**
- `runCAIssueCert()` - добавлена поддержка флага `--csr`
- `runOCSPServe()` - исправлена работа с `crypto.Signer`
- Исправлен конфликт имён `crypto` → `internalcrypto`

### `Makefile`
**Добавлены новые цели для Спринта 6:**
- `test-sprint6` - запуск тестов спринта 6
- `test-client-gen-csr` - тест генерации CSR
- `test-client-request` - тест запроса сертификата
- `test-client-validate` - тест валидации
- `test-client-check-status` - тест проверки отзыва
- `test-revocation-full` - полный тест отзыва

**Улучшена очистка:**
- `clean-pki` - очистка PKI файлов
- `clean-logs` - очистка логов
- `clean-temp` - очистка временных файлов
- `clean` - комбинированная очистка
- `clean-all` - полная очистка включая go mod cache

**Изменён `test-all`:**
- Убраны вызовы bash-скриптов
- Оставлены только Go-тесты (модульные + интеграционные)

### `scripts/test-all.sh`
**Изменён:**
- Использует `setup-pki.sh` для создания структуры
- Использует `run-all.sh` для запуска сервисов
- Использует `stop-all.sh` для остановки сервисов
- Улучшена обработка ошибок (продолжение при некритичных ошибках)
- Добавлена проверка существования скриптов

### `scripts/setup-pki.sh`
**Изменён:**
- Исправлено несоответствие Organization (O) - все используют `O=MicroPKI Test`
- Файлы паролей создаются в `pki/` директории

### `scripts/run-all.sh`
**Изменён:**
- Улучшен запуск сервисов с проверкой PID
- Добавлен вывод статуса

### `scripts/stop-all.sh`
**Изменён:**
- Улучшена остановка сервисов (поиск по PID)
- Добавлена принудительная очистка оставшихся процессов

## 3. Удаленные файлы
- `cmd/micropki-client` (отдельный клиентский бинарник не создавался, функционал интегрирован в основной CLI)
- Временные отладочные файлы (удаляются при `make clean`)

## 4. Ключевые изменения в функциональности

### Новые клиентские возможности:

1. **Генерация CSR** (CLI-25):
   - Поддержка RSA (2048/4096) и ECC (256/384) ключей
   - SAN: DNS, IP, email, URI
   - Сохранение ключа с правами 0600
   - Предупреждение о незашифрованном ключе

2. **Отправка CSR в репозиторий** (CLI-26, CLI-30, REPO-15):
   - HTTP POST `/request-cert?template=...`
   - Content-Type: application/x-pem-file
   - Опциональная аутентификация через X-API-Key
   - Получение подписанного сертификата

3. **Валидация цепочек** (CLI-27, VAL-1, VAL-2, VAL-5, VAL-6):
   - Построение пути от конечного до доверенного корня
   - Проверка подписи, срока действия, Basic Constraints, Key Usage
   - Поддержка `--validation-time` для тестирования
   - Вывод в форматах text/json

4. **Проверка отзыва с fallback** (CLI-28, REV-1, REV-2, REV-3):
   - Приоритет: OCSP → CRL
   - Извлечение OCSP URL из AIA
   - Извлечение CRL URL из CDP
   - Кэширование результатов
   - Детальный вывод статуса с причиной и временем

### Расширения CA и репозитория:

5. **Подписание внешних CSR** (CLI-29, CA-1):
   - Флаг `--csr` в команде `ca issue-cert`
   - Извлечение субъекта, SAN и ключа из CSR
   - Проверка подписи CSR
   - Запрет на запрос CA прав для конечных сертификатов

6. **Новый endpoint `/request-cert`** (REPO-15):
   - Интеграция с `IssueCertificateFromCSR()`
   - Логирование всех запросов (IP, шаблон, статус)
   - Возврат 201 Created с сертификатом

### Улучшения валидации:

7. **Построение цепочек** (VAL-1):
   - Рекурсивный поиск издателя
   - Проверка Authority Key ID и Subject Key ID
   - Обнаружение циклов

8. **Базовая проверка** (VAL-2):
   - Signature validity
   - Validity period
   - Basic Constraints (CA=true/false)
   - Path length constraints
   - Key Usage

### Контроль отзыва:

9. **OCSP клиент** (REV-2, REV-4):
   - Построение OCSP запроса с SHA-1 хешами
   - Отправка через HTTP POST
   - Парсинг ответа и извлечение статуса
   - Поддержка nonce

10. **CRL клиент** (REV-1, REV-5):
    - Загрузка CRL по HTTP или из файла
    - Проверка подписи CRL
    - Проверка nextUpdate
    - Поиск серийного номера

11. **Fallback логика** (REV-3):
    - Сначала OCSP
    - При неудаче - CRL
    - При обеих неудачах - unknown

12. **Кэширование** (REV-6):
    - Кэширование CRL и OCSP ответов
    - Инвалидация при отзыве
    - TTL настраивается

### Логирование и аудит:

13. **Логирование API запросов** (LOG-16):
    - Каждый запрос к `/request-cert` логируется
    - IP клиента, шаблон, статус, время обработки
    - Успешные выпуски с серийным номером

14. **Клиентское логирование** (LOG-14):
    - Генерация CSR, запросы сертификатов
    - Попытки валидации
    - Временные метки и результаты

15. **Машиночитаемый вывод** (LOG-15):
    - Флаг `--format json` для `client validate`
    - Структурированный результат с деталями