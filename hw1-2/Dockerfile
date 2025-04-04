# Этап сборки
FROM golang:1.21-alpine AS builder

# Установка зависимостей
RUN apk add --no-cache openssl git

# Копируем исходный код
WORKDIR /app
COPY . .

# Генерируем CA сертификаты
RUN chmod +x ./bin/gen_ca.sh && ./bin/gen_ca.sh

# Собираем приложение
RUN go build -o proxy ./cmd/main.go

# Финальный образ
FROM alpine:latest

# Устанавливаем необходимые пакеты
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    nss-tools \ # Для Firefox
    curl

# Создаем рабочую директорию
WORKDIR /app

# Копируем бинарник и сертификаты
COPY --from=builder /app/proxy .
COPY --from=builder /app/ca.crt .
COPY --from=builder /app/ca.key .
COPY --from=builder /app/cert.key .
COPY --from=builder /app/cfg/config.yaml ./cfg/

# Создаем директории для сертификатов
RUN mkdir -p /app/certs && \
    chmod 0755 /app/certs

# Скрипт для установки CA сертификата
COPY --from=builder /app/bin/gen_ca.sh ./bin/
RUN chmod +x ./bin/gen_ca.sh

# Устанавливаем CA сертификат в доверенные
RUN mkdir -p /usr/local/share/ca-certificates/ && \
    cp ca.crt /usr/local/share/ca-certificates/proxy-ca.crt && \
    update-ca-certificates && \
    # Для Firefox
    mkdir -p $HOME/.pki/nssdb && \
    certutil -d sql:$HOME/.pki/nssdb -N --empty-password && \
    certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Proxy CA" -i ca.crt

# Открываем порт прокси
EXPOSE 8080

# Точка входа
CMD ["/app/proxy"]