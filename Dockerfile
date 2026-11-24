# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETARM

WORKDIR /src
COPY go.mod *.go ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETARM} \
    go build -trimpath -ldflags="-s -w" -o /out/ip-api .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ip-api /ip-api

EXPOSE 8080
ENTRYPOINT ["/ip-api"]
