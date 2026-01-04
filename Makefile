# Build variables
BINARY_NAME := kubectl-rbac_why
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)"

# Go variables
GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

# Tool versions
GOLANGCI_LINT_VERSION := v1.55.2
KIND_VERSION := v0.20.0

.PHONY: all
all: build

##@ Development

.PHONY: build
build: ## Build the binary
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/kubectl-rbac_why

.PHONY: install
install: build ## Install to GOBIN
	cp bin/$(BINARY_NAME) $(GOBIN)/$(BINARY_NAME)

.PHONY: uninstall
uninstall: ## Remove from GOBIN
	rm -f $(GOBIN)/$(BINARY_NAME)

.PHONY: kubectl-setup
kubectl-setup: build ## Install plugin and verify kubectl can find it
	@echo "Installing kubectl plugin to $(GOBIN)..."
	@mkdir -p $(GOBIN)
	cp bin/$(BINARY_NAME) $(GOBIN)/$(BINARY_NAME)
	@echo ""
	@echo "Verifying installation..."
	@if kubectl plugin list 2>/dev/null | grep -q rbac-why || kubectl plugin list 2>/dev/null | grep -q rbac_why; then \
		echo "✓ Plugin installed successfully!"; \
		echo ""; \
		echo "Usage:"; \
		echo "  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get secrets -n default"; \
	else \
		echo "⚠ Warning: kubectl cannot find the plugin. Make sure $(GOBIN) is in your PATH."; \
		echo ""; \
		echo "Add to your ~/.zshrc or ~/.bashrc:"; \
		echo "  export PATH=\"$(GOBIN):\$$PATH\""; \
	fi

.PHONY: run
run: build ## Run the plugin with ARGS
	./bin/$(BINARY_NAME) $(ARGS)

.PHONY: fmt
fmt: ## Format code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

##@ Testing

.PHONY: test
test: ## Run unit tests
	go test -v -race -coverprofile=coverage.out ./pkg/...

.PHONY: test-short
test-short: ## Run unit tests (short mode)
	go test -v -short ./pkg/...

.PHONY: test-coverage
test-coverage: test ## Show test coverage
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

.PHONY: test-e2e
test-e2e: build ## Run e2e tests (requires kind cluster)
	go test -v -timeout 30m ./test/e2e/...

.PHONY: test-all
test-all: test test-e2e ## Run all tests

##@ Dependencies

.PHONY: deps
deps: ## Download dependencies
	go mod download
	go mod tidy

.PHONY: deps-update
deps-update: ## Update dependencies
	go get -u ./...
	go mod tidy

.PHONY: tools
tools: ## Install development tools
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "Installing kind..."
	go install sigs.k8s.io/kind@$(KIND_VERSION)

##@ Kind Cluster

.PHONY: kind-create
kind-create: ## Create a kind cluster for testing
	kind create cluster --name rbac-why-dev --wait 60s
	@echo "Cluster created. Run 'kubectl cluster-info' to verify."

.PHONY: kind-delete
kind-delete: ## Delete the kind cluster
	kind delete cluster --name rbac-why-dev

.PHONY: kind-setup-rbac
kind-setup-rbac: ## Setup test RBAC resources in kind cluster
	kubectl apply -f test/e2e/testdata/manifests/

.PHONY: kind-test
kind-test: build kind-setup-rbac ## Run manual test in kind cluster
	./bin/$(BINARY_NAME) can-i --as system:serviceaccount:test-ns:test-sa get secrets -n test-ns

.PHONY: e2e
e2e: ## Complete e2e workflow: create kind cluster, setup, test, and cleanup
	@echo "Starting complete e2e test workflow..."
	@echo ""
	@echo "Step 1/5: Creating kind cluster..."
	@kind get clusters | grep -q rbac-why-dev || $(MAKE) kind-create
	@echo ""
	@echo "Step 2/5: Building binary..."
	@$(MAKE) build
	@echo ""
	@echo "Step 3/5: Setting up RBAC resources..."
	@$(MAKE) kind-setup-rbac
	@echo ""
	@echo "Step 4/5: Running e2e tests..."
	@RBAC_WHY_BINARY=./bin/$(BINARY_NAME) go test -v -timeout 30m ./test/e2e/...
	@echo ""
	@echo "Step 5/5: E2E tests completed successfully!"
	@echo ""
	@echo "To cleanup: make e2e-cleanup"

.PHONY: e2e-cleanup
e2e-cleanup: ## Cleanup e2e test environment (delete kind cluster)
	@echo "Cleaning up e2e test environment..."
	@$(MAKE) kind-delete
	@echo "Cleanup complete!"

##@ Docker (optional)

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t kubectl-rbac-why:$(VERSION) .

##@ Release

.PHONY: release-snapshot
release-snapshot: ## Build release snapshot (no publish)
	goreleaser release --snapshot --clean

.PHONY: release
release: ## Create a release (requires GITHUB_TOKEN)
	goreleaser release --clean

##@ Clean

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

##@ Verification

.PHONY: verify
verify: fmt vet lint test ## Run all verification checks

.PHONY: verify-deps
verify-deps: ## Verify go.mod is tidy
	go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "go.mod/go.sum is not tidy, run 'go mod tidy'" && exit 1)

##@ Help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "\033[1mUsage Examples:\033[0m"
	@echo ""
	@echo "\033[1m  Install as kubectl plugin:\033[0m"
	@echo "    $$ make kubectl-setup"
	@echo "    $$ kubectl rbac-why --help"
	@echo ""
	@echo "\033[1m  Basic Permission Check:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get secrets -n default"
	@echo ""
	@echo "\033[1m  Check Cluster-Wide Permissions:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:kube-system:admin list nodes"
	@echo ""
	@echo "\033[1m  Check Subresource Access:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:default:debug-sa create pods/exec -n default"
	@echo ""
	@echo "\033[1m  JSON Output:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get pods -o json"
	@echo ""
	@echo "\033[1m  GraphViz Visualization:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get pods -o dot | dot -Tpng > rbac.png"
	@echo ""
	@echo "\033[1m  Risky Permissions Analysis:\033[0m"
	@echo "    $$ kubectl rbac-why can-i --as system:serviceaccount:default:my-sa --show-risky -n default"
	@echo ""
	@echo "\033[1m  Complete E2E Testing:\033[0m"
	@echo "    $$ make e2e                  # Full e2e workflow (cluster + tests)"
	@echo "    $$ make e2e-cleanup          # Cleanup e2e environment"
	@echo ""
	@echo "\033[1m  Manual Kind Cluster Testing:\033[0m"
	@echo "    $$ make kind-create          # Create test cluster"
	@echo "    $$ make kind-setup-rbac      # Setup test RBAC resources"
	@echo "    $$ make kind-test            # Run test query"
	@echo "    $$ make kind-delete          # Cleanup"
	@echo ""

.DEFAULT_GOAL := help
