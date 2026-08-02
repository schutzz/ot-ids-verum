# --- build stage ---
FROM alpine:latest AS build
RUN apk add --no-cache clang llvm bpftool libbpf-dev \
    linux-headers musl-dev make zlib-dev elfutils-dev zstd-dev binutils lld gcc curl-dev openssl-dev

WORKDIR /src
COPY . .

RUN clang -O2 -g -target bpf -c tx_prog.bpf.c -o tx_prog.bpf.o
RUN bpftool gen skeleton tx_prog.bpf.o > tx_prog.skel.h

RUN clang -O2 -o loader loader.c -lbpf -lelf -lz -lzstd -lcurl -lssl -lcrypto

# --- runtime stage ---
FROM alpine:latest
RUN apk add --no-cache libbpf libelf zstd-libs curl openssl
COPY --from=build /src/loader /loader
ENTRYPOINT ["/loader"]
