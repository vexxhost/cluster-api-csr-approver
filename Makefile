# Copyright 2026 VEXXHOST, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL := /usr/bin/env bash -o pipefail
.DEFAULT_GOAL := help

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TOOLS_BIN_DIR := $(ROOT_DIR)/hack/tools/bin
ENVTEST_DIR := $(ROOT_DIR)/hack/tools/envtest
OUT_DIR := $(ROOT_DIR)/out
ARTIFACTS ?= $(ROOT_DIR)/_artifacts
export PATH := $(TOOLS_BIN_DIR):$(PATH)

# Tool versions follow Cluster API v1.14.
CONTROLLER_GEN_VER := v0.21.0
KUSTOMIZE_VER := v5.7.0
SETUP_ENVTEST_VER := v0.24.1
GOLANGCI_LINT_VER := v2.12.2
GINKGO_VER := $(shell go list -m -f '{{.Version}}' github.com/onsi/ginkgo/v2)
KUBEBUILDER_ENVTEST_KUBERNETES_VERSION ?= 1.37.0

CONTROLLER_GEN := $(TOOLS_BIN_DIR)/controller-gen-$(CONTROLLER_GEN_VER)
KUSTOMIZE := $(TOOLS_BIN_DIR)/kustomize-$(KUSTOMIZE_VER)
SETUP_ENVTEST := $(TOOLS_BIN_DIR)/setup-envtest-$(SETUP_ENVTEST_VER)
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VER)
GINKGO := $(TOOLS_BIN_DIR)/ginkgo-$(GINKGO_VER)

# Image and version.
REGISTRY ?= ghcr.io/vexxhost
IMAGE_NAME ?= cluster-api-csr-approver
TAG ?= dev
IMG ?= $(REGISTRY)/$(IMAGE_NAME):$(TAG)
PLATFORMS ?= linux/amd64,linux/arm64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.0.0-dev)
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w \
	-X 'sigs.k8s.io/cluster-api/version.gitVersion=$(VERSION)' \
	-X 'sigs.k8s.io/cluster-api/version.gitCommit=$(GIT_COMMIT)' \
	-X 'sigs.k8s.io/cluster-api/version.buildDate=$(BUILD_DATE)'

# E2E.
E2E_IMG ?= $(REGISTRY)/$(IMAGE_NAME):e2e
E2E_CONF_FILE ?= $(ROOT_DIR)/test/e2e/config/e2e.yaml
GINKGO_FOCUS ?=
GINKGO_SKIP ?=
GINKGO_NODES ?= 1
GINKGO_TIMEOUT ?= 2h
SKIP_RESOURCE_CLEANUP ?= false
USE_EXISTING_CLUSTER ?= false

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: $(CONTROLLER_GEN) ## Generate RBAC manifests from kubebuilder markers.
	$(CONTROLLER_GEN) rbac:roleName=manager-role paths="./..." output:rbac:artifacts:config=config/rbac

.PHONY: fmt
fmt: ## Run go fmt.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet, including the e2e package.
	go vet ./...
	go vet -tags e2e ./test/e2e/...

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint.
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) run --build-tags e2e ./test/e2e/...

.PHONY: verify
verify: generate ## Verify generated files and go.mod are up to date.
	go mod tidy
	@if [ -n "$$(git status --porcelain -- go.mod go.sum config)" ]; then \
		git status --porcelain -- go.mod go.sum config; git diff -- go.mod go.sum config; \
		echo "generated files are out of date, run 'make generate' and 'go mod tidy'"; exit 1; \
	fi

##@ Testing

.PHONY: test
test: $(SETUP_ENVTEST) ## Run unit and envtest integration tests.
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(KUBEBUILDER_ENVTEST_KUBERNETES_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" \
	REQUIRE_ENVTEST=1 \
	go test -race -coverprofile=$(OUT_DIR)/cover.out ./... $(TEST_ARGS)

.PHONY: test-e2e
test-e2e: $(GINKGO) $(KUSTOMIZE) docker-build-e2e ## Run the end-to-end tests with kind and CAPD.
	mkdir -p $(ARTIFACTS)
	CAPI_KUSTOMIZE_PATH=$(KUSTOMIZE) \
	$(GINKGO) -v --trace --tags=e2e --timeout=$(GINKGO_TIMEOUT) --nodes=$(GINKGO_NODES) \
		--focus="$(GINKGO_FOCUS)" --skip="$(GINKGO_SKIP)" \
		--output-dir="$(ARTIFACTS)" --junit-report="junit.e2e_suite.xml" \
		./test/e2e -- \
		-e2e.config="$(E2E_CONF_FILE)" \
		-e2e.artifacts-folder="$(ARTIFACTS)" \
		-e2e.skip-resource-cleanup=$(SKIP_RESOURCE_CLEANUP) \
		-e2e.use-existing-cluster=$(USE_EXISTING_CLUSTER)

##@ Build

.PHONY: build
build: ## Build the manager binary.
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/manager .

.PHONY: docker-build
docker-build: ## Build the container image.
	docker build --build-arg LDFLAGS="$(LDFLAGS)" -t $(IMG) .

.PHONY: docker-build-e2e
docker-build-e2e: ## Build the container image used by the e2e tests.
	$(MAKE) docker-build IMG=$(E2E_IMG)

.PHONY: release-manifests
release-manifests: $(KUSTOMIZE) ## Build the clusterctl release assets into out/ for IMG.
	mkdir -p $(OUT_DIR)
	rm -rf $(OUT_DIR)/kustomize && cp -r config $(OUT_DIR)/kustomize
	cd $(OUT_DIR)/kustomize/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build $(OUT_DIR)/kustomize/default > $(OUT_DIR)/addon-components.yaml
	rm -rf $(OUT_DIR)/kustomize
	cp metadata.yaml $(OUT_DIR)/metadata.yaml

##@ Tools

$(CONTROLLER_GEN):
	GOBIN=$(TOOLS_BIN_DIR) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VER)
	mv $(TOOLS_BIN_DIR)/controller-gen $@

$(KUSTOMIZE):
	GOBIN=$(TOOLS_BIN_DIR) go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VER)
	mv $(TOOLS_BIN_DIR)/kustomize $@

$(SETUP_ENVTEST):
	GOBIN=$(TOOLS_BIN_DIR) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VER)
	mv $(TOOLS_BIN_DIR)/setup-envtest $@

$(GOLANGCI_LINT):
	GOBIN=$(TOOLS_BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	mv $(TOOLS_BIN_DIR)/golangci-lint $@

$(GINKGO):
	GOBIN=$(TOOLS_BIN_DIR) go install github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VER)
	mv $(TOOLS_BIN_DIR)/ginkgo $@

$(OUT_DIR):
	mkdir -p $@

test: | $(OUT_DIR)
