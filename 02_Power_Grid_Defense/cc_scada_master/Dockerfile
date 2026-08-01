FROM python:3.10-slim

WORKDIR /app

# Install OS utilities if needed for debugging
RUN apt-get update && apt-get install -y iproute2 iputils-ping curl && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY scada_mtu_server.py .

# Start script to add routes and run server
CMD bash -c "ip route add 10.0.20.0/24 via 10.0.10.254 && ip route add 10.0.30.0/24 via 10.0.10.254 && python -u scada_mtu_server.py"
