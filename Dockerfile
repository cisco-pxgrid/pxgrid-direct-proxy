FROM rust:1.88-alpine AS build
WORKDIR /build
RUN apk add --no-cache ca-certificates gcc musl-dev
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM scratch
COPY --from=build /build/target/release/api-pagination-proxy /api-pagination-proxy
# Keep the standard Alpine CA bundle in the scratch image for public HTTPS.
# A private bundle can be bind-mounted at runtime; configure ca_bundle_path.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY config.yaml /etc/api-proxy/config.yaml
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EXPOSE 3030
ENTRYPOINT ["/api-pagination-proxy"]
