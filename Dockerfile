# Build the crx-manifest-audit CLI as a static binary, then ship it on a
# minimal Alpine base. No network access is performed at run time.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/crx-manifest-audit ./cmd/crx-manifest-audit

FROM alpine:3.22
LABEL org.opencontainers.image.title="crx-manifest-audit" \
      org.opencontainers.image.description="Command-line auditor for Chromium extension manifest.json files (Manifest V2 and V3)." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/theluckystrike/crx-manifest-parser" \
      org.opencontainers.image.url="https://zovo.one/permissions"
RUN adduser -D -u 10001 audit
COPY --from=build /out/crx-manifest-audit /usr/local/bin/crx-manifest-audit
COPY LICENSE /LICENSE
USER audit
WORKDIR /work
ENTRYPOINT ["crx-manifest-audit"]
CMD ["-h"]
