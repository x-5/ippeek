# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

RUN apk add --no-cache upx

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETARM

WORKDIR /src
COPY go.mod *.go ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETARM} \
    go build -trimpath -ldflags="-s -w" -o /out/ippeek . && \
    (upx --best --lzma /out/ippeek || true)

FROM scratch
COPY --from=builder /out/ippeek /ippeek

EXPOSE 8080
ENTRYPOINT ["/ippeek"]
