FROM rust:1.80-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/sensor-emulator /app/sensor-emulator
EXPOSE 502
CMD ["/app/sensor-emulator"]
