import urllib.request, json
from datetime import datetime, timezone

now = datetime.now(timezone.utc).isoformat()

nodes = [
    {'id': '10.0.10.10', '@timestamp': now, 'title': '10.0.10.10', 'subTitle': 'Source Node', 'mainStat': 'Active', 'arc__color': 'blue'},
    {'id': '10.0.30.10', '@timestamp': now, 'title': '10.0.30.10', 'subTitle': 'Target Node', 'mainStat': 'Active', 'arc__color': 'blue'},
    {'id': '172.16.0.99', '@timestamp': now, 'title': '172.16.0.99', 'subTitle': 'Attacker', 'mainStat': 'Active', 'arc__color': 'red'}
]

edges = [
    {'id': '10.0.10.10-10.0.30.10', '@timestamp': now, 'source': '10.0.10.10', 'target': '10.0.30.10', 'mainStat': 'DNP3 FC: READ', 'thickness': 3, 'color': 'blue'},
    {'id': '172.16.0.99-10.0.30.10', '@timestamp': now, 'source': '172.16.0.99', 'target': '10.0.30.10', 'mainStat': 'DNP3 FC: DIRECT_OPERATE', 'thickness': 3, 'color': 'red'}
]

for n in nodes:
    url = f'http://localhost:9200/ot-topology-nodes-2026.08.06/_doc/{n["id"]}'
    req = urllib.request.Request(url, data=json.dumps(n).encode(), headers={'Content-Type': 'application/json'}, method='PUT')
    urllib.request.urlopen(req)

for e in edges:
    url = f'http://localhost:9200/ot-topology-edges-2026.08.06/_doc/{e["id"]}'
    req = urllib.request.Request(url, data=json.dumps(e).encode(), headers={'Content-Type': 'application/json'}, method='PUT')
    urllib.request.urlopen(req)

print('Correct schema injected.')
