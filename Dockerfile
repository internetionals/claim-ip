FROM rust:slim-buster AS buildenv

COPY . /build
WORKDIR /build
RUN cargo build --release

FROM debian:buster-slim

COPY --from=buildenv /build/target/release/claim-ip /usr/local/bin/

ENTRYPOINT [ "claim-ip" ]
