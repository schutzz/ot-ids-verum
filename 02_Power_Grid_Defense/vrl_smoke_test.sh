#!/bin/bash
# vrl_smoke_test.sh
set -e
echo "Running VRL smoke tests..."

extract_vrl() {
  local transform_name=$1
  awk "/\[transforms.${transform_name}\]/ {flag=1} flag && /source = '''/ {flag=2; next} flag==2 && /'''/ {flag=0; exit} flag==2 {print}" vector/vector.toml
}

echo "Testing build_topology_edges..."
VRL_EDGES=$(extract_vrl "build_topology_edges")
if [ -z "$VRL_EDGES" ]; then
  echo "Error: Could not extract VRL for build_topology_edges"
  exit 1
fi

echo "$VRL_EDGES" > test_edges.vrl
echo '{"tags":{"network_src_ip":"10.0.10.10","network_dest_ip":"10.0.30.10"},"fc":5,"color":"red"}' > test_edges.json
docker cp test_edges.vrl vector:/tmp/test_edges.vrl
docker cp test_edges.json vector:/tmp/test_edges.json

RESULT=$(docker exec vector vector vrl -p /tmp/test_edges.vrl -i /tmp/test_edges.json)

if echo "$RESULT" | grep -q '"thickness"' && ! echo "$RESULT" | grep -q '"arc__thickness"'; then
  echo "✅ build_topology_edges: Field names are correct."
else
  echo "❌ build_topology_edges: Validation failed."
  echo "Output was:"
  echo "$RESULT"
  exit 1
fi

echo "Testing build_topology_nodes..."
VRL_NODES=$(extract_vrl "build_topology_nodes")
if [ -z "$VRL_NODES" ]; then
  echo "Error: Could not extract VRL for build_topology_nodes"
  exit 1
fi

echo "$VRL_NODES" > test_nodes.vrl
echo '{"tags":{"network_src_ip":"10.0.10.10"},"color":"red"}' > test_nodes.json
docker cp test_nodes.vrl vector:/tmp/test_nodes.vrl
docker cp test_nodes.json vector:/tmp/test_nodes.json

RESULT=$(docker exec vector vector vrl -p /tmp/test_nodes.vrl -i /tmp/test_nodes.json)

if ! echo "$RESULT" | grep -q '"node__id"'; then
  echo "✅ build_topology_nodes: Field names are correct."
else
  echo "❌ build_topology_nodes: Validation failed."
  echo "Output was:"
  echo "$RESULT"
  exit 1
fi

echo "All VRL smoke tests passed successfully!"
