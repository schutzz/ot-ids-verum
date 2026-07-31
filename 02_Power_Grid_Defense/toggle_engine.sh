#!/bin/bash
MODE=$1
if [ "$MODE" == "legacy" ]; then
    echo "Starting legacy (Zeek) engine..."
    docker-compose --profile ebpf stop ebpf_agent
    docker-compose --profile legacy up -d zeek_tap
elif [ "$MODE" == "ebpf" ]; then
    echo "Starting eBPF engine (Standalone)..."
    docker-compose --profile legacy stop zeek_tap
    docker-compose --profile ebpf up -d ebpf_agent
elif [ "$MODE" == "hybrid" ]; then
    echo "Starting HYBRID engine (eBPF Vanguard + Zeek Rearguard)..."
    docker-compose --profile ebpf up -d ebpf_agent
    docker-compose --profile legacy up -d zeek_tap
else
    echo "Usage: $0 [legacy|ebpf|hybrid]"
    exit 1
fi
