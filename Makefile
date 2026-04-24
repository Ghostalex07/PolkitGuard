.PHONY: all build test build-local install clean lint vet check run run-test deps docker-build docker-run release man

BINARY_NAME=polkitguard
VERSION=$(shell cat internal/config/config.go | grep 'Version.*=' | head -1 | awk -F'"' '{print $$2}')
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
all: build test lint

# Build
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/scan

build-local:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/scan

# Install
install:
	go install $(LDFLAGS) ./cmd/scan

# Run
run:
	go run $(LDFLAGS) ./cmd/scan --path testdata

run-test:
	go run $(LDFLAGS) ./cmd/scan --path testdata --severity high

run-json:
	go run $(LDFLAGS) ./cmd/scan --path testdata --format json --severity high

run-quiet:
	go run $(LDFLAGS) ./cmd/scan --path testdata --severity high -q

# Test
test:
	go test -v -coverprofile=coverage.out ./...

test-quick:
	go test ./...

test-detector:
	go test -v -run TestDetect ./...

test-bench:
	go test -bench=. -benchtime=1s ./...

# Lint
lint: vet
	@echo "Running linters..."

vet:
	go vet ./...

check: lint test

# Clean
clean:
	rm -rf bin/ coverage.out

# Docker
docker-build:
	docker build -t ghostalex07/polkitguard:latest .

docker-run:
	docker run --rm -v /etc/polkit-1:/etc/polkit-1:ro ghostalex07/polkitguard:latest --path /etc/polkit-1

docker-run-test:
	docker run --rm -v $$(pwd)/testdata:/testdata:ro ghostalex07/polkitguard:latest --path /testdata

# Release
release:
	goreleaser release --clean

snapshot:
	goreleaser build --snapshot --clean

# Completion
completion-bash:
	go run ./cmd/scan completion bash > completions/polkitguard.bash
	@echo "Bash completions saved to completions/polkitguard.bash"

completion-zsh:
	go run ./cmd/scan completion zsh > completions/polkitguard.zsh
	@echo "Zsh completions saved to completions/polkitguard.zsh"

# Man page
man:
	go run ./cmd/scan completion man > docs/polkitguard.1
	@echo "Man page generated"

# Config
config-gen:
	@echo "Generating config.example.json..."
	@echo '{"version":"1.5.0","severity_filter":"low","output_format":"text","ignore_paths":["test-","backup-"]}' > config.example.json

deps:
	go mod download
	go mod tidy