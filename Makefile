.DEFAULT_GOAL := help

GO ?= go
BUILD_DIR := dist
TIMEOUT ?= 300s
PKG ?= ./...
GOLANGCI := golangci-lint

##@ Development

.PHONY: build
build: ## Build the opnsense-uxg binary
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -o $(BUILD_DIR)/opnsense-uxg ./cmd/opnsense-uxg

.PHONY: cross
cross: ## Cross-compile for Linux and FreeBSD on amd64 and arm64
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/opnsense-uxg_linux_amd64 ./cmd/opnsense-uxg
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/opnsense-uxg_linux_arm64 ./cmd/opnsense-uxg
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/opnsense-uxg_freebsd_amd64 ./cmd/opnsense-uxg
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 $(GO) build -o $(BUILD_DIR)/opnsense-uxg_freebsd_arm64 ./cmd/opnsense-uxg

.PHONY: test
test: ## Run tests (make test PKG=./tests/... TIMEOUT=60s)
	$(GO) test -timeout $(TIMEOUT) $(PKG)

.PHONY: test-race
test-race: ## Run tests with the race detector
	$(GO) test -race -timeout $(TIMEOUT) $(PKG)

.PHONY: test-sdk
test-sdk: ## Run the local SDK unit tests and vet (no live acceptance tests)
	cd ../opnsense-go && $(GO) test -race -timeout $(TIMEOUT) ./pkg/api ./pkg/diagnostics ./internal/generate/...
	cd ../opnsense-go && $(GO) vet ./pkg/api ./pkg/diagnostics ./internal/generate/...

.PHONY: cover
cover: ## Write a coverage report under dist
	@mkdir -p $(BUILD_DIR)
	$(GO) test -timeout $(TIMEOUT) -coverpkg=./internal/... -coverprofile=$(BUILD_DIR)/coverage.out $(PKG)
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

.PHONY: fmt
fmt: ## Format Go source
	$(GOLANGCI) fmt

.PHONY: fmt-check
fmt-check: ## Check Go formatting
	@test -z "$$(gofmt -l cmd internal tests)" || (gofmt -l cmd internal tests; exit 1)

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI) config verify
	$(GOLANGCI) run

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

.PHONY: validate
validate: ## Validate the example configuration without network access
	$(GO) run ./cmd/opnsense-uxg -validate -config config.example.yaml

.PHONY: check
check: fmt-check vet lint test-race test-sdk validate cross ## Format check, vet, lint, bridge/SDK race tests, config and cross-builds

##@ Cleanup

.PHONY: clean
clean: ## Remove build outputs
	rm -rf $(BUILD_DIR)

##@ Help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
