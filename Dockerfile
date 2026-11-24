# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETARM
ARG BUILD_TAGS=""
ARG VERSION="dev"
ARG USE_UPX="false"

RUN if [ "${USE_UPX}" = "true" ]; then apk add --no-cache upx; fi

WORKDIR /src
COPY go.mod *.go ./

RUN set -e; \
    TAGS_FLAG=""; \
    if [ -n "${BUILD_TAGS}" ]; then TAGS_FLAG="-tags=${BUILD_TAGS}"; fi; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" GOARM="${TARGETARM}" \
    go build -trimpath ${TAGS_FLAG} \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/ippeek .; \
    if [ "${USE_UPX}" = "true" ]; then upx --best --lzma /out/ippeek || true; fi

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ippeek /ippeek

EXPOSE 8080
ENTRYPOINT ["/ippeek"]
