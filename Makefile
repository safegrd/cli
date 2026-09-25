SHELL := /bin/bash

MODULE     := github.com/safegrd/cli
VERSION    ?= 0.0.1
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X $(MODULE)/internal/cli.Version=$(VERSION) -X $(MODULE)/internal/cli.Commit=$(GIT_COMMIT) -X $(MODULE)/internal/cli.Date=$(BUILD_DATE)

BIN_DIR := bin
CLI_BIN := $(BIN_DIR)/safegrd

.PHONY: help all build dist test vet fmt tidy clean ci check-fmt check-tidy

.DEFAULT_GOAL := help

help: ## Display this help message
	@echo "SafeGrd CLI: Build & Test"
	@echo "==========================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

all: build test ## Build binary and run tests

build: ## Compile safegrd CLI binary
	@mkdir -p $(BIN_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(CLI_BIN) ./cmd/safegrd
	@echo "Built $(CLI_BIN) version $(VERSION) ($(GIT_COMMIT))"

test: ## Run unit and integration tests with race detector
	go test -v -race ./...

vet: fmt tidy
	go vet ./...

fmt: ## Format Go code
	go fmt ./...

tidy: ## Tidy Go module dependencies
	go mod tidy

dist: ## Cross-compile release archives and checksums into dist/
	@set -euo pipefail; \
	rm -rf dist; mkdir -p dist; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
	  goos="$${target%/*}"; goarch="$${target#*/}"; \
	  name="safegrd_$(VERSION)_$${goos}_$${goarch}"; \
	  echo "Compiling $${goos}/$${goarch}..."; \
	  mkdir -p "dist/$${name}"; \
	  CGO_ENABLED=0 GOOS="$${goos}" GOARCH="$${goarch}" \
	    go build -trimpath -ldflags="$(LDFLAGS)" -o "dist/$${name}/safegrd" ./cmd/safegrd; \
	  cp LICENSE NOTICE README.md "dist/$${name}/"; \
	  (cd dist && tar -czf "$${name}.tar.gz" "$${name}"); \
	  rm -rf "dist/$${name}"; \
	done; \
	(cd dist && shasum -a 256 safegrd_*.tar.gz > checksums.txt); \
	echo "Checksums:"; cat dist/checksums.txt

# CI runs these instead of `vet`, because `vet` depends on fmt and tidy, which
# rewrite files: a formatting gate that formats for you always passes.
#
# `ci` depends on `build` because `go vet` and `go test` can succeed even if
# the main command package is missing or misconfigured. Compiling ensures
# cmd/safegrd builds successfully.
check-fmt: ## Fail if any file needs gofmt
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "These files need gofmt:"; echo "$$out"; exit 1; fi

check-tidy: ## Fail if go.mod or go.sum are not tidy
	go mod tidy
	git diff --exit-code go.mod go.sum

ci: check-fmt check-tidy build ## Run every gate CI runs
	go vet ./...
	go test -race ./...

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html dist
