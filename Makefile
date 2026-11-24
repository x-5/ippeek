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
	@echo "Targets (all Go builds/tests run inside Docker $(GO_IMAGE)):"
	@echo "  make vet          - Run go vet"
	@echo "  make test         - Run all unit and TCP 444 integration tests"
	@echo "  make build        - Build static linux/amd64 binary to $(DIST_DIR)/$(APP_NAME)"
	@echo "  make build-all    - Cross-compile static binaries for all major hardware platforms"
	@echo "  make docker-image - Build minimal FROM scratch Docker image ($(APP_NAME):latest)"
	@echo "  make clean        - Remove $(DIST_DIR)"

vet:
	$(DOCKER_GO) go vet ./...

test:
	$(DOCKER_GO) go test -v ./...

build:
	@mkdir -p $(DIST_DIR)
	$(DOCKER_GO) sh -c 'GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) .'

build-all:
	@mkdir -p $(DIST_DIR)
	$(DOCKER_GO) sh -c '\
		set -e; \
		GOOS=linux   GOARCH=amd64                 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 .; \
		GOOS=linux   GOARCH=arm64                 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 .; \
		GOOS=linux   GOARCH=arm     GOARM=7       go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-armv7 .; \
		GOOS=linux   GOARCH=arm     GOARM=6       go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-armv6 .; \
		GOOS=linux   GOARCH=mipsle  GOMIPS=softfloat go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-mipsle-softfloat .; \
		GOOS=linux   GOARCH=mips    GOMIPS=softfloat go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-mips-softfloat .; \
		GOOS=linux   GOARCH=riscv64               go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-linux-riscv64 .; \
		GOOS=windows GOARCH=amd64                 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe .; \
		GOOS=darwin  GOARCH=arm64                 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 .; \
		GOOS=darwin  GOARCH=amd64                 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 .; \
	'
	@ls -lh $(DIST_DIR)/

docker-image:
	docker build -t $(APP_NAME):latest .

clean:
	rm -rf $(DIST_DIR)
