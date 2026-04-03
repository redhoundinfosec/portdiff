BINARY     := portdiff
MODULE     := github.com/redhoundinfosec/portdiff
VERSION    := 0.1.0
BUILD_DIR  := dist
CMD        := ./cmd/portdiff

# Build variables
LDFLAGS    := -ldflags "-s -w -X main.version=$(VERSION)"
GOFLAGS    :=

# Go tool path
GOBIN      ?= $(shell go env GOPATH)/bin

.PHONY: all build test lint clean release install help

all: build

## build: Build the binary for the current platform
build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

## install: Install the binary to GOBIN
install:
	go install $(LDFLAGS) $(CMD)

## test: Run all unit tests with verbose output
test:
	go test ./... -v -count=1 -race

## test-short: Run tests without the race detector (faster)
test-short:
	go test ./... -count=1

## lint: Run go vet and check formatting
lint:
	go vet ./...
	@echo "Checking formatting..."
	@test -z "$$(gofmt -l . | grep -v vendor)" || (echo "Files not properly formatted:" && gofmt -l . && exit 1)

## tidy: Run go mod tidy
tidy:
	go mod tidy

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)

## release: Cross-compile for Linux, macOS, and Windows
release: clean
	mkdir -p $(BUILD_DIR)

	# Linux amd64
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   $(CMD)
	# Linux arm64
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   $(CMD)
	# macOS amd64 (Intel)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  $(CMD)
	# macOS arm64 (Apple Silicon)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  $(CMD)
	# Windows amd64
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)

	@echo ""
	@echo "Release binaries:"
	@ls -lh $(BUILD_DIR)/

## demo: Run a demo diff using the example files
demo: build
	@echo ""
	@echo "=== Text output ==="
	./$(BINARY) diff examples/scan-before.xml examples/scan-after.xml --no-color || true
	@echo ""
	@echo "=== JSON output ==="
	./$(BINARY) diff examples/scan-before.xml examples/scan-after.xml -f json || true
	@echo ""
	@echo "=== Summary ==="
	./$(BINARY) summary examples/scan-before.xml --no-color || true

## help: Show this help message
help:
	@echo "portdiff Makefile"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/  /'
