FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .
RUN go build -o polkitguard ./cmd/scan

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/polkitguard .

ENV PATH=/app:$PATH

ENTRYPOINT ["/app/polkitguard"]