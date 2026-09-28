# runeward control plane, MCP server, and Kubernetes controller (one binary).
FROM --platform=$BUILDPLATFORM golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-s -w -X github.com/Runewardd/runeward/internal/cli.version=${VERSION}" \
    -o /out/runeward ./cmd/runeward

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
LABEL org.opencontainers.image.source="https://github.com/Runewardd/runeward"
LABEL org.opencontainers.image.description="Governed execution cells for AI agents"
# MCP registry OCI ownership check: the value MUST equal the server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.Runewardd/runeward"
COPY --from=build /out/runeward /usr/local/bin/runeward
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/runeward"]
CMD ["serve", "--port", "8080"]
