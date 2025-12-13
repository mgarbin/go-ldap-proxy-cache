# Makefile for go-ldap-proxy-cache

.PHONY: build clean test run install help

# Build the binary
build:
	go build -o ldap-proxy .

# Build with version info
build-release:
	go build -ldflags="-s -w" -o ldap-proxy .

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f ldap-proxy coverage.out coverage.html

# Run the proxy with default settings
run: build
	./ldap-proxy

# Install dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Run linters
lint:
	go vet ./...

# Install to system
install:
	go install .

help:
	@echo "Available targets:"
	@echo "  build          - Build the LDAP proxy binary"
	@echo "  build-release  - Build optimized release binary"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  clean          - Remove build artifacts"
	@echo "  run            - Build and run the proxy"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  fmt            - Format code"
	@echo "  lint           - Run linters"
	@echo "  install        - Install to $GOPATH/bin"
