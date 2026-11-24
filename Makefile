GO_IMAGE ?= golang:1.23-alpine
APP_NAME ?= ip-api
DIST_DIR ?= dist
LDFLAGS  := -s -w

DOCKER_GO := docker run --rm \
	-u $$(id -u):$$(id -g) \
	-v "$(CURDIR):/src" \
	-w /src \
	-e GOCACHE=/tmp/gocache \
	-e GOPATH=/tmp/gopath \
	-e CGO_ENABLED=0 \
	$(GO_IMAGE)

.PHONY: help vet test build build-all docker-image clean

help:
	@echo "go-tiny targets (runs inside Docker $(GO_IMAGE) + UPX):"
	@echo "  make vet          - Run go vet"
	@echo "  make test         - Run all unit and raw-TCP 444 tests"
	@echo "  make build        - Build & UPX-compress static linux/amd64 binary"
	@echo "  make build-all    - Cross-compile & UPX-compress binaries for all hardware platforms"
	@echo "  make docker-image - Build minimal FROM scratch Docker image ($(APP_NAME):go-tiny)"
	@echo "  make clean        - Remove $(DIST_DIR)"

vet:
	$(DOCKER_GO) go vet ./...

test:
	$(DOCKER_GO) go test -v ./...

build:
	@mkdir -p $(DIST_DIR)
	docker run --rm -v "$(CURDIR):/src" -w /src -e GOCACHE=/tmp/gocache -e CGO_ENABLED=0 $(GO_IMAGE) sh -c '\
		set -e; \
		apk add --no-cache -q upx; \
		GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) .; \
		upx --best --lzma -q $(DIST_DIR)/$(APP_NAME); \
		chown $$(id -u):$$(id -g) $(DIST_DIR)/$(APP_NAME) 2>/dev/null || true \
	'
	@ls -lh $(DIST_DIR)/$(APP_NAME)

build-all:
	@mkdir -p $(DIST_DIR)
	docker run --rm -v "$(CURDIR):/src" -w /src -e GOCACHE=/tmp/gocache -e CGO_ENABLED=0 $(GO_IMAGE) sh -c '\
		set -e; \
		apk add --no-cache -q upx; \
		GOOS=linux   GOARCH=amd64                    go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 .; \
		GOOS=linux   GOARCH=arm64                    go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 .; \
		GOOS=linux   GOARCH=arm     GOARM=7          go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-armv7 .; \
		GOOS=linux   GOARCH=arm     GOARM=6          go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-armv6 .; \
		GOOS=linux   GOARCH=mipsle  GOMIPS=softfloat go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-mipsle-softfloat .; \
		GOOS=linux   GOARCH=mips    GOMIPS=softfloat go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-mips-softfloat .; \
		GOOS=linux   GOARCH=riscv64                  go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-riscv64 .; \
		GOOS=windows GOARCH=amd64                    go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe .; \
		GOOS=darwin  GOARCH=arm64                    go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 .; \
		GOOS=darwin  GOARCH=amd64                    go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 .; \
		echo "=== Raw sizes (before UPX) ==="; \
		ls -lh $(DIST_DIR)/; \
		for f in \
			$(DIST_DIR)/$(APP_NAME)-linux-amd64 \
			$(DIST_DIR)/$(APP_NAME)-linux-arm64 \
			$(DIST_DIR)/$(APP_NAME)-linux-armv7 \
			$(DIST_DIR)/$(APP_NAME)-linux-armv6 \
			$(DIST_DIR)/$(APP_NAME)-linux-mipsle-softfloat \
			$(DIST_DIR)/$(APP_NAME)-linux-mips-softfloat \
			$(DIST_DIR)/$(APP_NAME)-windows-amd64.exe; do \
			upx --best --lzma -q "$$f" || true; \
		done; \
		chown -R $(shell id -u):$(shell id -g) $(DIST_DIR) \
	'
	@echo "=== Final sizes (after UPX) ==="
	@ls -lh $(DIST_DIR)/

docker-image:
	docker build -t $(APP_NAME):go-tiny .

clean:
	rm -rf $(DIST_DIR)
