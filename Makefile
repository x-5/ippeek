GO_IMAGE   ?= golang:1.23-alpine
APP_NAME   ?= ippeek
DIST_DIR   ?= dist
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TAGS ?= tiny
USE_UPX    ?= false
LDFLAGS    := -s -w -X main.version=$(VERSION)
HOST_UID   := $(shell id -u)
HOST_GID   := $(shell id -g)

DOCKER_GO := docker run --rm \
	-u $(HOST_UID):$(HOST_GID) \
	-v "$(CURDIR):/src" \
	-w /src \
	-e GOCACHE=/tmp/gocache \
	-e GOPATH=/tmp/gopath \
	-e CGO_ENABLED=0 \
	$(GO_IMAGE)

DOCKER_GO_ROOT := docker run --rm \
	-v "$(CURDIR):/src" \
	-w /src \
	-e GOCACHE=/tmp/gocache \
	-e GOPATH=/tmp/gopath \
	-e CGO_ENABLED=0 \
	$(GO_IMAGE)

.PHONY: help vet test check-tiny-deps build build-all docker-image clean

help:
	@echo "Targets (all Go builds/tests run inside Docker $(GO_IMAGE)):"
	@echo "  make vet             - Run go vet for both std and -tags tiny"
	@echo "  make test            - Run unit and 444 integration tests for both std and -tags tiny"
	@echo "  make check-tiny-deps - Verify -tags tiny does not link net/http, crypto/tls, reflect, etc."
	@echo "  make build           - Build std, tiny, and tiny-upx linux/amd64 binaries into $(DIST_DIR)/"
	@echo "  make build-all       - Cross-compile all 3 editions (std, tiny, tiny-upx) + checksums.txt"
	@echo "  make docker-image    - Build minimal FROM scratch image (BUILD_TAGS=$(BUILD_TAGS), USE_UPX=$(USE_UPX))"
	@echo "  make clean           - Remove $(DIST_DIR)"

vet:
	$(DOCKER_GO) go vet ./...
	$(DOCKER_GO) go vet -tags tiny ./...

test:
	$(DOCKER_GO) go test -v ./...
	$(DOCKER_GO) go test -tags tiny -v ./...

check-tiny-deps:
	$(DOCKER_GO) sh -c 'if go list -tags tiny -deps . | grep -E "^(net/http|crypto/tls|encoding/json|reflect|fmt|flag|log)$$"; then echo "ERROR: forbidden package linked in tiny build" >&2; exit 1; fi; echo "OK: tiny build has zero forbidden stdlib dependencies"'

build:
	@mkdir -p $(DIST_DIR)
	$(DOCKER_GO_ROOT) sh -c '\
		set -e; \
		apk add --no-cache -q upx; \
		GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-std-linux-amd64 .; \
		GOOS=linux GOARCH=amd64 go build -trimpath -tags tiny -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-tiny-linux-amd64 .; \
		cp -f $(DIST_DIR)/$(APP_NAME)-tiny-linux-amd64 $(DIST_DIR)/$(APP_NAME)-tiny-upx-linux-amd64; \
		upx --best --lzma -q $(DIST_DIR)/$(APP_NAME)-tiny-upx-linux-amd64; \
		chown -R $(HOST_UID):$(HOST_GID) $(DIST_DIR) \
	'
	@ls -lh $(DIST_DIR)/$(APP_NAME)-*-linux-amd64

build-all:
	@rm -rf $(DIST_DIR) && mkdir -p $(DIST_DIR)
	$(DOCKER_GO_ROOT) sh -c '\
		set -e; \
		apk add --no-cache -q upx; \
		build_matrix() { \
			prefix="$$1"; tags="$$2"; \
			tflag=""; \
			if [ -n "$$tags" ]; then tflag="-tags=$$tags"; fi; \
			GOOS=linux   GOARCH=amd64                    go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-amd64 .; \
			GOOS=linux   GOARCH=arm64                    go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-arm64 .; \
			GOOS=linux   GOARCH=arm     GOARM=7          go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-armv7 .; \
			GOOS=linux   GOARCH=arm     GOARM=6          go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-armv6 .; \
			GOOS=linux   GOARCH=mipsle  GOMIPS=softfloat go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-mipsle-softfloat .; \
			GOOS=linux   GOARCH=mips    GOMIPS=softfloat go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-mips-softfloat .; \
			GOOS=linux   GOARCH=riscv64                  go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-linux-riscv64 .; \
			GOOS=windows GOARCH=amd64                    go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-windows-amd64.exe .; \
			GOOS=darwin  GOARCH=arm64                    go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-darwin-arm64 .; \
			GOOS=darwin  GOARCH=amd64                    go build -trimpath $$tflag -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$${prefix}-darwin-amd64 .; \
		}; \
		build_matrix "$(APP_NAME)-std"  ""; \
		build_matrix "$(APP_NAME)-tiny" "tiny"; \
		for arch in linux-amd64 linux-arm64 linux-armv7 linux-armv6 linux-mipsle-softfloat linux-mips-softfloat windows-amd64.exe; do \
			cp -f "$(DIST_DIR)/$(APP_NAME)-tiny-$${arch}" "$(DIST_DIR)/$(APP_NAME)-tiny-upx-$${arch}"; \
			upx --best --lzma -q "$(DIST_DIR)/$(APP_NAME)-tiny-upx-$${arch}"; \
		done; \
		(cd $(DIST_DIR) && sha256sum $(APP_NAME)-* > checksums.txt); \
		chown -R $(HOST_UID):$(HOST_GID) $(DIST_DIR) \
	'
	@ls -lh $(DIST_DIR)/

docker-image:
	docker build \
		--build-arg BUILD_TAGS="$(BUILD_TAGS)" \
		--build-arg VERSION="$(VERSION)" \
		--build-arg USE_UPX="$(USE_UPX)" \
		-t $(APP_NAME):latest .

clean:
	rm -rf $(DIST_DIR)
