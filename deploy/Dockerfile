# runeward control plane, MCP server, and Kubernetes controller (one binary).

# runeward from the Rust workspace. Built natively for the target platform
# (no --platform=$BUILDPLATFORM: the Alpine/musl toolchain links a static
# binary for the distroless runtime below without a cross linker; the
# release workflow builds each architecture on a native runner). TLS is
# rustls with ring; no OpenSSL or aws-lc.
FROM rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Embedded at compile time: the web dashboard and the Kubernetes install
# manifests and CRDs.
COPY web ./web
COPY internal/manifests ./internal/manifests
# Stamped into `runeward version` by crates/runeward-cli/build.rs.
ARG VERSION=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    RUNEWARD_VERSION="${VERSION#v}" \
    cargo build --release --locked -p runeward-cli --bin runeward \
    && install -D -m 0755 target/release/runeward /out/runeward

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
LABEL org.opencontainers.image.source="https://github.com/Runewardd/runeward"
LABEL org.opencontainers.image.description="Rune Box: an environment where your agent can roam freely but securely"
# MCP registry OCI ownership check: the value MUST equal the server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.Runewardd/runeward"
COPY --from=build /out/runeward /usr/local/bin/runeward
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/runeward"]
CMD ["serve", "--port", "8080"]
