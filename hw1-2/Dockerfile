FROM golang:1.21 as builder

WORKDIR /app
COPY . .

RUN go mod init proxy
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy ./cmd/main.go

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/proxy .
COPY ./cfg/config.yaml ./cfg/config.yaml

EXPOSE 8080
CMD ["./proxy"]