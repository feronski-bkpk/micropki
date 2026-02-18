# MicroPKI - Минимальная инфраструктура публичных ключей

MicroPKI — это профессиональный инструмент командной строки для создания и управления корневым центром сертификации (Root CA) с акцентом на безопасность, соответствие стандартам X.509 и простоту использования.

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
  - RSA 4096 бит
  - ECC P-384 (secp384r1)
- **Создание самоподписанных X.509v3 сертификатов** со всеми необходимыми расширениями:
  - Basic Constraints (CA=TRUE, критическое)
  - Key Usage (keyCertSign, cRLSign, критическое)
  - Subject Key Identifier (SKI)
  - Authority Key Identifier (AKI)
- **Безопасное хранение ключей**:
  - Шифрование AES-256-GCM с PBKDF2 (600,000 итераций)
  - Права доступа 0600 для ключей, 0700 для директорий
- **Подробное логирование** всех операций
- **Генерация политики безопасности** (policy.txt)

### **Безопасность**
- Использование только криптостойких алгоритмов
- Защита от padding oracle атак (AES-GCM)
- Безопасное затирание паролей в памяти
- Проверка соответствия ключа и сертификата
- Верификация самоподписанных сертификатов

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

# 3. Создайте файл с паролем
echo "ваш-надежный-пароль" > pass.txt

# 4. Создайте корневой CA
./micropki-cli ca init \
  --subject "/CN=Мой Корневой CA/O=Моя Организация/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file pass.txt \
  --out-dir ./my-pki \
  --validity-days 3650 \
  --log-file ./ca-init.log

# 5. Проверьте результат
./micropki-cli ca verify --cert ./my-pki/certs/ca.cert.pem
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

### Команда `ca verify`

Проверка самоподписанного сертификата.

```bash
./micropki-cli ca verify --cert ./pki/certs/ca.cert.pem
```

## Примеры

### Пример 1: Создание RSA корневого CA на 10 лет

```bash
# Подготовка
mkdir -p secrets
echo "MySecurePassphrase123" > secrets/root-ca.pass
chmod 600 secrets/root-ca.pass

# Создание CA
./micropki-cli ca init \
  --subject "/CN=Production Root CA/O=My Company/C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file secrets/root-ca.pass \
  --out-dir ./production-pki \
  --validity-days 3650 \
  --log-file ./logs/ca-init.log

# Результат:
# ./production-pki/certs/ca.cert.pem
# ./production-pki/private/ca.key.pem (зашифрован)
# ./production-pki/policy.txt
```

### Пример 2: Создание ECC корневого CA (P-384)

```bash
./micropki-cli ca init \
  --subject "CN=ECC Root CA, O=MicroPKI, C=RU" \
  --key-type ecc \
  --key-size 384 \
  --passphrase-file pass.txt \
  --out-dir ./ecc-pki
```

### Пример 3: Проверка сертификата OpenSSL

```bash
# Просмотр содержимого сертификата
openssl x509 -in ./pki/certs/ca.cert.pem -text -noout

# Проверка подписи
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem

# Извлечение публичного ключа
openssl x509 -in ./pki/certs/ca.cert.pem -pubkey -noout
```

### Пример 4: Расшифровка приватного ключа

```bash
# Просмотр зашифрованного ключа
cat ./pki/private/ca.key.pem

# Расшифровка (потребуется пароль)
openssl pkey -in ./pki/private/ca.key.pem -passin pass:MySecurePassphrase123\!@# -text -noout
```

## Структура проекта

```
micropki/
├── micropki/                      # Основной пакет
│   ├── cmd/
│   │   └── micropki/              # Точка входа CLI
│   │       └── main.go
│   └── internal/                  # Внутренние пакеты
│       ├── ca/                    # Логика CA
│       ├── certs/                 # X.509 операции
│       └── crypto/                # Криптография
├── tests/                         # Интеграционные тесты
├── scripts/                       # Вспомогательные скрипты
├── Makefile                       # Автоматизация сборки
├── go.mod                         # Зависимости Go
└── README.md                      # Этот файл
```

**Выходная структура PKI (`--out-dir`):**
```
my-pki/
├── private/
│   └── ca.key.pem          # Зашифрованный приватный ключ (0600)
├── certs/
│   └── ca.cert.pem          # Сертификат CA (0644)
└── policy.txt               # Документ политики безопасности
```

## Безопасность

### Криптографические стандарты

| Компонент | Технология | Обоснование |
|-----------|------------|-------------|
| **RSA ключи** | 4096 бит | Промышленный стандарт, устойчив к квантовым атакам |
| **ECC ключи** | P-384 (NIST) | Рекомендовано NSA для высшей секретности |
| **Шифрование ключей** | AES-256-GCM | Аутентифицированное шифрование, защита от padding oracle |
| **Производные ключи** | PBKDF2, 600,000 итераций | OWASP рекомендации |
| **Серийные номера** | 160 бит CSPRNG | Предотвращение коллизий |

### Рекомендации по эксплуатации

1. **Храните пароли надёжно**: Используйте менеджеры паролей
2. **Резервное копирование**: Сохраняйте копии `private/` в защищённом месте
3. **Ограничьте доступ**: Только администраторы PKI должны иметь доступ к приватным ключам
4. **Мониторинг**: Анализируйте логи на предмет подозрительной активности
5. **Регулярные проверки**: Периодически проверяйте сертификаты на валидность

## Тестирование

### Запуск тестов

```bash
# Все тесты
make test

# Подробный вывод
make test-verbose

# С покрытием
make test-coverage

# Открыть отчёт о покрытии
# После make test-coverage откройте coverage.html в браузере
```

## Makefile команды

| Команда | Описание |
|---------|----------|
| `make build` | Собрать бинарный файл |
| `make clean` | Удалить все сгенерированные файлы |
| `make test` | Запустить тесты |
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
