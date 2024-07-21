FROM golang:1.16 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go get -d -v . && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/smtp_exporter .
ENTRYPOINT [ "./smtp_exporter" ]
CMD ["--web.listen-address=0.0.0.0:9125", "--log.level=info", "--config.file=smtp.yml"]
