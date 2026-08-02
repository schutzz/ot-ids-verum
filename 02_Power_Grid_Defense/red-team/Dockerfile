FROM alpine:latest

# Install Python3, Docker CLI (to run docker exec for mock Zeek log injection), and curl
RUN apk add --no-cache python3 py3-pip docker-cli curl

# Ensure stdout is unbuffered for Python scripts
ENV PYTHONUNBUFFERED=1

WORKDIR /attacks

# Keep the container running for C2 orchestration / manual exec
CMD ["tail", "-f", "/dev/null"]
