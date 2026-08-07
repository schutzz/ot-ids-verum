FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    tcpdump \
    iputils-ping \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-20.10.9.tgz | tar xzvf - --strip-components=1 -C /usr/local/bin docker/docker

RUN pip3 install --no-cache-dir scapy

CMD bash -c "ip route replace 10.0.10.0/24 via 172.16.0.254 && ip route replace 10.0.20.0/24 via 172.16.0.254 && ip route replace 10.0.30.0/24 via 172.16.0.254 && echo 'External Attacker node ready.' && tail -f /dev/null"
