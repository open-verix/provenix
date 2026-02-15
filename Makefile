.PHONY: help build test lint clean install run

# Variables
BINARY_NAME=provenix
VERSION?=dev
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X github.com/open-verix/provenix/internal/cli.Version=$(VERSION) -X github.com/open-verix/provenix/internal/cli.GitCommit=$(GIT_COMMIT) -X github.com/open-verix/provenix/internal/cli.BuildDate=$(BUILD_DATE)"

# UPX compression (optional - requires upx to be installed)
# Install: brew install upx (macOS), apt-get install upx (Linux)
UPX?=

# Enable verbose output with VERBOSE=1
VERBOSE?=

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
ifdef VERBOSE
	@echo "=========================================="
	@echo "Building $(BINARY_NAME)..."
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "=========================================="
	@go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/provenix
	@echo "✅ Build successful: ./$(BINARY_NAME)"
	@echo ""
	@./$(BINARY_NAME) version 2>/dev/null || echo "Binary version: $(VERSION) ($(GIT_COMMIT))"
else
	@go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/provenix
endif

install: ## Install the binary to $(GOPATH)/bin
ifdef VERBOSE
	@echo "=========================================="
	@echo "Installing $(BINARY_NAME)..."
	@echo "Version:    $(VERSION)"
	@echo "=========================================="
	@go install $(LDFLAGS) ./cmd/provenix
	@echo "✅ Installation successful"
	@which $(BINARY_NAME)
else
	@go install $(LDFLAGS) ./cmd/provenix
endif

test: ## Run unit tests
	go test -v -race -coverprofile=coverage.out ./...

test-integration: ## Run integration tests
	go test -v -tags=integration ./test/integration/...

test-e2e: ## Run end-to-end tests
	go test -v -tags=e2e ./test/e2e/...

test-all: test test-integration test-e2e ## Run all tests

coverage: test ## Generate coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf dist/ build/

run: build ## Build and run
	./$(BINARY_NAME)

deps: ## Download dependencies
	go mod download
	go mod verify

deps-update: ## Update dependencies (use with caution)
	go get -u=patch ./...
	go mod tidy

verify: ## Verify dependencies and run checks
	go mod verify
	go vet ./...
	golangci-lint run
	go test -short ./...

build-verbose: ## Build with verbose output
	@echo "=========================================="
	@echo "Building $(BINARY_NAME) (verbose mode)..."
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"
	@echo "LDFLAGS:    $(LDFLAGS)"
	@echo "=========================================="
	go build -v $(LDFLAGS) -o $(BINARY_NAME) ./cmd/provenix
	@echo ""
	@echo "✅ Build successful: ./$(BINARY_NAME)"
	@ls -lh $(BINARY_NAME)

build-info: ## Build with version info output (same as VERBOSE=1 make build)
	@$(MAKE) VERBOSE=1 build

quick: ## Quick build without version info
	@go build -o $(BINARY_NAME) ./cmd/provenix && echo "✅ Quick build: ./$(BINARY_NAME)"

build-small: ## Build with maximum size optimization (slower startup)
	@echo "Building optimized binary (this may take a while)..."
	@CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o $(BINARY_NAME) ./cmd/provenix
	@echo "✅ Optimized build complete"
	@ls -lh $(BINARY_NAME)
ifdef UPX
	@echo "Compressing with UPX..."
	@upx -q --best --lzma $(BINARY_NAME) 2>/dev/null || upx -q --best $(BINARY_NAME)
	@echo "✅ Compressed binary:"
	@ls -lh $(BINARY_NAME)
endif

size-analysis: ## Analyze binary size breakdown
	@echo "Binary size analysis:"
	@ls -lh $(BINARY_NAME)
	@echo ""
	@echo "Top 20 largest dependencies:"
	@go list -m all | head -20
	@echo ""
	@echo "Total dependencies: $$(go list -m all | wc -l | tr -d ' ')"

# Removed - 'build' is now quiet by default, use 'build-info' or VERBOSE=1 for output

.DEFAULT_GOAL := help
