# webpush-server with every bridge and the Bigtable adapter.
#
#   docker build -t webpush-server .
#   docker run -p 8443:8443 -p 8081:8081 \
#     -v $PWD/webpush.toml:/etc/webpush/webpush.toml:ro \
#     -e WEBPUSH_CONFIG=/etc/webpush/webpush.toml webpush-server
#
# Configuration comes from the file named by WEBPUSH_CONFIG, if set, and from
# WEBPUSH_* environment variables, which win. Without a file, environment
# variables alone configure the service (WEBPUSH_ORIGIN at minimum).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p webpush-server --features bigtable \
    && cp target/release/webpush-server /webpush-server

# Distroless: glibc and CA certificates, no shell, runs as uid 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /webpush-server /usr/local/bin/webpush-server
EXPOSE 8443 8081
ENTRYPOINT ["/usr/local/bin/webpush-server"]
