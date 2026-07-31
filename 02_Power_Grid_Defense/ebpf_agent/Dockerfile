# --- build stage ---
FROM alpine:latest AS build
RUN apk add --no-cache clang llvm bpftool libbpf-dev \
    linux-headers musl-dev make zlib-dev zlib-static elfutils-dev zstd-dev zstd-static
WORKDIR /src
COPY . .

RUN clang -O2 -g -target bpf -c xdp_prog.bpf.c -o xdp_prog.bpf.o
RUN bpftool gen skeleton xdp_prog.bpf.o > xdp_prog.skel.h

RUN clang -O2 -static -o loader loader.c -lbpf -lelf -lz -lzstd

# --- runtime stage ---
FROM scratch
COPY --from=build /src/loader /loader
ENTRYPOINT ["/loader"]
