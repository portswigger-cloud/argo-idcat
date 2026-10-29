# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd

# Adapted from https://github.com/LukeMathWalker/cargo-chef
FROM rust:1.97-slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1.97-slim-trixie AS builder
WORKDIR /build
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --locked --release
# Rust's std links libgcc_s for unwinding. It is the only library the binary
# needs beyond glibc, so take it alone, at its multiarch path, rather than the
# whole of distroless/cc.
RUN mkdir /runtime-libs && cp --parents /usr/lib/*-linux-gnu/libgcc_s.so.1 /runtime-libs/

FROM gcr.io/distroless/base-nossl-debian13:nonroot

COPY --from=builder /runtime-libs/ /
COPY --from=builder /build/target/release/argo-idcat /

EXPOSE 8181 8182
ENTRYPOINT ["/argo-idcat"]
