#!/bin/bash

echo "========================================="
echo "ТЕСТИРОВАНИЕ ДЕТЕКЦИИ АНОМАЛИЙ"
echo "========================================="

# Сохраняем текущий лог
cp ./pki/audit/audit.log ./pki/audit/audit.log.backup

# 1. Нормальная активность (уже есть в логе)
echo -e "\n1. Анализ нормальной активности:"
./micropki-cli audit detect-anomalies --window 1

# 2. Генерация аномалии - всплеск выпусков
echo -e "\n2. Генерация всплеска активности (10 выпусков за 10 секунд)..."
for i in {1..10}; do
    ./micropki-cli ca issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file <(echo -n "intpass123") \
        --template server \
        --subject "CN=spike-$i.local" \
        --san "dns:spike-$i.local" \
        --out-dir /tmp \
        --validity-days 365 \
        --db-path ./pki/micropki.db > /dev/null 2>&1
done
echo "10 сертификатов выпущено"

echo -e "\n3. Анализ после всплеска:"
./micropki-cli audit detect-anomalies --window 1

# 3. Генерация аномалии - много отзывов
echo -e "\n4. Генерация аномалии (5 отзывов)..."
# Получаем серийные номера последних сертификатов
SERIALS=$(sqlite3 ./pki/micropki.db "SELECT serial_hex FROM certificates WHERE subject LIKE '%spike%' LIMIT 5;")
for serial in $SERIALS; do
    ./micropki-cli ca revoke \
        "$serial" \
        --reason superseded \
        --force \
        --db-path ./pki/micropki.db > /dev/null 2>&1
done
echo "5 сертификатов отозвано"

echo -e "\n5. Анализ после отзывов:"
./micropki-cli audit detect-anomalies --window 1

# 4. Генерация аномалии - много ошибок
echo -e "\n6. Генерация аномалии (много ошибок)..."
for i in {1..15}; do
    ./micropki-cli ca issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file <(echo -n "intpass123") \
        --template server \
        --subject "CN=error-$i.local" \
        --san "dns:*.error-$i.local" \
        --out-dir /tmp \
        --validity-days 365 \
        --db-path ./pki/micropki.db > /dev/null 2>&1
done
echo "15 попыток с wildcard (все должны быть заблокированы)"

echo -e "\n7. Анализ после ошибок:"
./micropki-cli audit detect-anomalies --window 1

# 5. Показать подробную статистику по операциям
echo -e "\n8. Подробная статистика операций:"
echo "Операции в аудите:"
grep -o '"operation":"[^"]*"' ./pki/audit/audit.log | sort | uniq -c | sort -rn

echo -e "\n========================================="
echo "ТЕСТИРОВАНИЕ ЗАВЕРШЕНО"
echo "========================================="

# Восстанавливаем лог
mv ./pki/audit/audit.log.backup ./pki/audit/audit.log
echo "Лог восстановлен"
