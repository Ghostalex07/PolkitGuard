.POLKITGUARD

# Build
build:
	go build -o polkitguard ./cmd/scan

# Install
install:
	go install ./cmd/scan

# Test
test:
	go test -v ./...

# Vet
vet:
	go vet ./...

# Format
fmt:
	gofmt -w .

# Build all platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o bin/polkitguard-linux-amd64 ./cmd/scan
	GOOS=linux GOARCH=arm64 go build -o bin/polkitguard-linux-arm64 ./cmd/scan

# Clean
clean:
	rm -f polkitguard
	rm -rf bin/

# Run with test data
run-test:
	./polkitguard --path ./testdata

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  install    - Install binary"
	@echo "  test       - Run tests"
	@echo "  vet        - Run go vet"
	@echo "  fmt        - Format code"
	@echo "  build-all  - Build for all platforms"
	@echo "  clean      - Clean build artifacts"
	@echo "  run-test   - Run with test data"