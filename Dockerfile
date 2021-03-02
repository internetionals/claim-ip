FROM rust:alpine3.13 AS buildenv

COPY . /build
WORKDIR /build
RUN cargo build --release

FROM alpine:3.13

COPY --from=buildenv /build/target/release/claim-ip /usr/local/bin/

ENTRYPOINT [ "claim-ip" ]
