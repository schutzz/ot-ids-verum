#!/bin/bash
set -e

echo "[+] Zero Trust OT/ICS Local Docker Lab のカプセル化展開を開始するっス！"

LAB_DIR="ot_zero_trust_lab"
mkdir -p ./${LAB_DIR}/grafana/provisioning/datasources
mkdir -p ./${LAB_DIR}/grafana/provisioning/dashboards
mkdir -p ./${LAB_DIR}/nginx
mkdir -p ./${LAB_DIR}/ot-ids
mkdir -p ./${LAB_DIR}/ot_data
cd ./${LAB_DIR}

cat << 'EOF' > grafana/provisioning/dashboards/dashboards.yaml
apiVersion: 1
providers:
  - name: 'OT Zero Trust Substation'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

cat << 'EOF' > grafana/provisioning/datasources/datasource.yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    version: 1
    editable: false
EOF

cat << 'EOF' > nginx/nginx.conf
events {}
http {
    server {
        listen 3100;
        
        location /loki/api/v1/push {
            if ($http_authorization != "Bearer SuperSecretToken2026") {
                return 401 "Unauthorized: Invalid or Missing Bearer Token";
            }
            proxy_pass http://loki:3100;
        }
    }
}
EOF

cat << 'EOF' > ot-ids/virtual_substation.py
import json, time, random, os
LOG_FILE = "/var/log/ot_data/ids.json"
def log_event(event_type, action, status, threat_level="info"):
    event = {
        "attributes": {"time": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())},
        "substation": "Kyiv-North-330kV", "protocol": "IEC-60870-5-104",
        "event": event_type, "action": action, "threat_level": threat_level, "status": status
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"Logged: {event['action']}")
if __name__ == "__main__":
    if os.path.exists(LOG_FILE): os.remove(LOG_FILE)
    while True:
        log_event("ASDU_M_ME_NA_1", "Voltage_Check", "Normal")
        time.sleep(2)
        if random.randint(1, 5) == 1:
            print("[!] INCOMING ATTACK DETECTED")
            for ioa in range(401, 404):
                log_event("ASDU_C_SC_NA_1", f"BREAKER_OPEN_IOA_{ioa}", "Executed", "critical")
                time.sleep(0.5)
EOF

cat << 'EOF' > ot-ids/Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY virtual_substation.py .
CMD ["python", "-u", "virtual_substation.py"]
EOF

cat << 'EOF' > otel-collector-config.yaml
extensions:
  bearertokenauth:
    token: "SuperSecretToken2026"
receivers:
  filelog/ot_hmi:
    include: [ /var/log/ot_data/*.json ]
    start_at: beginning
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.time
          layout: '%Y-%m-%dT%H:%M:%S.%LZ'
processors:
  resource:
    attributes:
      - key: environment
        value: "zero-trust-lab"
        action: insert
      - key: architecture
        value: "pattern1-token-auth"
        action: insert
exporters:
  loki:
    endpoint: "http://loki-proxy:3100/loki/api/v1/push"
    auth:
      authenticator: bearertokenauth
service:
  extensions: [bearertokenauth]
  telemetry:
    logs:
      level: info
  pipelines:
    logs:
      receivers: [filelog/ot_hmi]
      processors: [resource]
      exporters: [loki]
EOF

cat << 'EOF' > docker-compose.yml
version: '3.8'
networks:
  ot_closed_net:
    driver: bridge
    internal: true
  mgmt_net:
    driver: bridge
services:
  loki:
    image: grafana/loki:2.9.2
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - ot_closed_net
      - mgmt_net
    restart: unless-stopped
  loki-proxy:
    image: nginx:alpine
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    networks:
      - ot_closed_net
    restart: unless-stopped
    depends_on:
      - loki
  grafana:
    image: grafana/grafana:10.2.2
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_AUTH_DISABLE_LOGIN_FORM=true
    ports:
      - "3000:3000"
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - mgmt_net
    restart: unless-stopped
    depends_on:
      - loki
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.91.0
    command: ["--config=/etc/otelcol-contrib/config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro
      - ./ot_data:/var/log/ot_data:ro
    networks:
      - ot_closed_net
    restart: unless-stopped
    depends_on:
      - loki-proxy
  ot-ids:
    build: ./ot-ids
    volumes:
      - ./ot_data:/var/log/ot_data
    networks:
      - ot_closed_net
    restart: unless-stopped
EOF

echo "[+] 設定ファイルの生成完了。Dockerコンテナをバックグラウンドで起動するっス！"
docker-compose up -d --build

echo "[+] 展開完了っス！"
echo "[!] ブラウザで http://localhost:3000 にアクセスして、Explore画面で {env=\"zero-trust-lab\"} を検索してくださいっス！"
