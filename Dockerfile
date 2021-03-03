FROM rust:alpine3.13 AS buildenv

RUN apk add libc-dev
COPY . /build
WORKDIR /build
RUN cargo build --release
RUN strip --strip-debug target/release/claim-ip

FROM scratch

COPY --from=buildenv /build/target/release/claim-ip /

ENTRYPOINT [ "/claim-ip" ]
