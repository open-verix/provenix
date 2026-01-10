.PHONY: help build test lint clean install run

# Variables
BINARY_NAME=provenix
VERSION?=dev
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X github.com/open-verix/provenix/internal/cli.Version=$(VERSION) -X github.com/open-verix/provenix/internal/cli.GitCommit=$(GIT_COMMIT) -X github.com/open-verix/provenix/internal/cli.BuildDate=$(BUILD_DATE)"

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/provenix

install: ## Install the binary to $(GOPATH)/bin
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) ./cmd/provenix

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

.DEFAULT_GOAL := help
