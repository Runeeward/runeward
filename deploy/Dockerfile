# runeward control plane, MCP server, and Kubernetes controller (one binary).

# runeward from the Rust workspace. Built natively for the target platform
# (no --platform=$BUILDPLATFORM: the Alpine/musl toolchain links a static
# binary for the distroless runtime below without a cross linker; the
# release workflow builds each architecture on a native runner). TLS is
# rustls with ring; no OpenSSL or aws-lc.
FROM rust:1.99-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Embedded at compile time: the web dashboard. (The Kubernetes manifests
# live in crates/runeward-k8s/manifests.)
COPY web ./web
# Stamped into `runeward version` by crates/runeward-cli/build.rs.
ARG VERSION=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    RUNEWARD_VERSION="${VERSION#v}" \
    cargo build --release --locked -p runeward-cli --bin runeward \
    && install -D -m 0755 target/release/runeward /out/runeward

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
LABEL org.opencontainers.image.source="https://github.com/Runeeward/runeward"
LABEL org.opencontainers.image.description="Rune Box: an environment where your agent can roam freely but with receipts"
# MCP registry OCI ownership check: the value MUST equal the server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.Runeeward/runeward"
COPY --from=build /out/runeward /usr/local/bin/runeward
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/runeward"]
CMD ["serve", "--port", "8080"]
