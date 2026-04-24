FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /polkitguard ./cmd/scan

FROM alpine:3.19

RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /polkitguard /usr/local/bin/polkitguard
COPY config.schema.json /usr/share/polkitguard/config.schema.json

RUN adduser -D polkituser && chown -R polkituser:polkituser /usr/share/polkitguard
USER polkituser

ENTRYPOINT ["/usr/local/bin/polkitguard"]
CMD ["--help"]