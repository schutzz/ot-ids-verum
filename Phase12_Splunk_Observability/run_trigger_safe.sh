#!/bin/bash
cd /mnt/c/Users/user/.gemini/antigravity/scratch
docker-compose up -d ot-ids

echo "Waiting for ot-ids to finish apt-get and pip install..."
while ! docker exec ot-ids ps -ef 2>/dev/null | grep -v grep | grep -q "python3 -u /ids/realtime_ids.py"; do
    # Fallback if ps is not installed
    if docker exec ot-ids sh -c 'ls /proc/*/cmdline 2>/dev/null | xargs -r cat | tr "\0" " " | grep -q "python3 -u /ids/realtime_ids.py"'; then
        break
    fi
    sleep 2
done

echo "IDS is running! Waiting an extra 3 seconds for it to bind ports..."
sleep 3

echo "Running trigger.py..."
docker exec ot-ids python3 /ids/trigger.py
