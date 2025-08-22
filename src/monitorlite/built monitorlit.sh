#!/usr/bin/env bash
set -euo pipefail

PROJECT=monitorlite
rm -rf "$PROJECT" monitorlite.zip
mkdir -p "$PROJECT"/{src/monitorlite,rules,logs,pcaps,tools,.github/workflows}

# -------------------- root files --------------------
cat > "$PROJECT/.gitignore" <<'EOF'
__pycache__/
*.pyc
.venv/
logs/
pcaps/*.pcap
.env
EOF

cat > "$PROJECT/LICENSE" <<'EOF'
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction... (use full MIT text if you want)
EOF

cat > "$PROJECT/requirements.txt" <<'EOF'
scapy==2.5.0
PyYAML==6.0.2
rich==13.7.1
EOF

cat > "$PROJECT/README.md" <<'EOF'
# MonitorLite
Lightweight IDS for learning and demos. Current milestone (50%): packet capture +
rule-based detection incl. basic DoS thresholding. Final goal: AI-based IDS.

## Quick start
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m monitorlite --pcap pcaps/sample.pcap --rules rules/example-basic.yml --eve logs/eve.json

## Live capture (lab only; requires sudo)
sudo python -m monitorlite --iface eth0 --rules rules/example-basic.yml --eve logs/eve.json

## Docker
docker build -t monitorlite .
docker run --rm -v $(pwd)/rules:/app/rules -v $(pwd)/logs:/app/logs -v $(pwd)/pcaps:/app/pcaps monitorlite \
  --pcap /app/pcaps/sample.pcap --rules /app/rules/example-basic.yml --eve /app/logs/eve.json

## Ethics
Use ONLY on networks/systems you own or have explicit written permission to test.
EOF

cat > "$PROJECT/Dockerfile" <<'EOF'
FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev iproute2 net-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "-m", "monitorlite"]
EOF

cat > "$PROJECT/docker-compose.yml" <<'EOF'
version: "3.8"
services:
  monitorlite:
    build: .
    volumes:
      - ./rules:/app/rules
      - ./logs:/app/logs
      - ./pcaps:/app/pcaps
    command: >
      --pcap /app/pcaps/sample.pcap
      --rules /app/rules/example-basic.yml
      --eve /app/logs/eve.json
    # For live capture (lab only), uncomment:
    # cap_add: [ "NET_ADMIN", "NET_RAW" ]
    # network_mode: host
    # command: >
    #   --iface eth0
    #   --rules /app/rules/example-basic.yml
    #   --eve /app/logs/eve.json
EOF

cat > "$PROJECT/.github/workflows/docker-build.yml" <<'EOF'
name: Build and Publish Docker Image
on:
  push: { branches: ["main"] }
  pull_request: { branches: ["main"] }
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.CR_PAT }}
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/monitorlite:latest
EOF

# -------------------- package: src/monitorlite --------------------
cat > "$PROJECT/src/monitorlite/__init__.py" <<'EOF'
__all__ = ["cli","capture","decoder","detection","logger","utils"]
EOF

# utils.py
cat > "$PROJECT/src/monitorlite/utils.py" <<'EOF'
from datetime import datetime, timezone
import json
def now_ts():
    return datetime.now(timezone.utc)
def iso(ts=None):
    return (ts or now_ts()).isoformat()
def to_json(obj):
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
EOF

# logger.py
cat > "$PROJECT/src/monitorlite/logger.py" <<'EOF'
from pathlib import Path
from rich.console import Console
from .utils import iso, to_json

console = Console()

class AlertSink:
    def __init__(self, eve_path=None, pretty_console=True):
        self.pretty_console = pretty_console
        self.eve_path = Path(eve_path) if eve_path else None
        self.fp = None
        if self.eve_path:
            self.eve_path.parent.mkdir(parents=True, exist_ok=True)
            self.fp = self.eve_path.open("a", buffering=1)
    def emit(self, event: dict):
        event.setdefault("event_type","alert")
        event.setdefault("timestamp", iso())
        line = to_json(event)
        if self.fp: self.fp.write(line + "\n")
        if self.pretty_console: console.print(f"[bold red]ALERT[/] {line}")
    def close(self):
        if self.fp: self.fp.close()
EOF

# decoder.py
cat > "$PROJECT/src/monitorlite/decoder.py" <<'EOF'
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
try:
    from scapy.layers.http import HTTPRequest
except Exception:
    HTTPRequest = None
from scapy.packet import Raw

def decode(pkt):
    out = {"l2": None,"src_mac": None,"dst_mac": None,
           "l3": None,"src_ip": None,"dst_ip": None,
           "l4": None,"src_port": None,"dst_port": None,
           "proto": None,"flags": [],
           "dns_qname": None,"http": {},
           "payload_len": 0,"payload": None}
    p = pkt
    if Ether in p:
        out["l2"] = "ethernet"; out["src_mac"] = p[Ether].src; out["dst_mac"] = p[Ether].dst
    if IP in p:
        out["l3"] = "ipv4"; out["src_ip"] = p[IP].src; out["dst_ip"] = p[IP].dst; out["proto"] = p[IP].proto
    if TCP in p:
        out["l4"] = "tcp"; out["src_port"] = int(p[TCP].sport); out["dst_port"] = int(p[TCP].dport)
        flags = p[TCP].flags
        out["flags"] = [f for f,b in {"F":1,"S":2,"R":4,"P":8,"A":16,"U":32,"E":64,"C":128}.items() if flags & b]
    elif UDP in p:
        out["l4"] = "udp"; out["src_port"] = int(p[UDP].sport); out["dst_port"] = int(p[UDP].dport)
    if DNS in p and p[DNS].qdcount > 0 and DNSQR in p:
        try: out["dns_qname"] = p[DNSQR].qname.decode("utf-8","ignore").rstrip(".")
        except Exception: out["dns_qname"] = None
    if HTTPRequest and HTTPRequest in p:
        h = p[HTTPRequest]
        out["http"] = {
            "host": bytes(getattr(h,"Host",b"") or b"").decode("latin-1","ignore"),
            "path": bytes(getattr(h,"Path",b"/") or b"/").decode("latin-1","ignore"),
            "method": bytes(getattr(h,"Method",b"") or b"").decode("latin-1","ignore"),
            "ua": bytes(getattr(h,"User_Agent",b"") or b"").decode("latin-1","ignore"),
        }
    if Raw in p:
        raw = bytes(p[Raw].load or b""); out["payload_len"] = len(raw)
        out["payload"] = raw[:256].decode("latin-1","ignore")
    return out
EOF

# capture.py
cat > "$PROJECT/src/monitorlite/capture.py" <<'EOF'
from scapy.all import sniff, PcapReader
def live_sniff(iface, bpf_filter, cb):
    sniff(iface=iface, filter=bpf_filter, prn=cb, store=False)
def pcap_iter(path):
    with PcapReader(path) as p:
        for pkt in p: yield pkt
EOF

# detection.py (rules + stateful tracking)
cat > "$PROJECT/src/monitorlite/detection.py" <<'EOF'
import re, yaml
from dataclasses import dataclass
from typing import Any, Dict, List
from collections import defaultdict, deque
from datetime import timedelta
from .utils import now_ts

@dataclass
class Rule:
    id: str
    title: str
    severity: str = "low"
    when: Dict[str, Any] = None
    flow: Dict[str, Any] = None
    enabled: bool = True
    tags: List[str] = None

def load_rules(path: str) -> List[Rule]:
    with open(path,"r") as f: raw = yaml.safe_load(f) or []
    rules=[]
    for r in raw:
        rules.append(Rule(
            id=str(r.get("id")),
            title=r.get("title","rule"),
            severity=r.get("severity","low"),
            when=r.get("when") or {},
            flow=r.get("flow") or {},
            enabled=bool(r.get("enabled",True)),
            tags=r.get("tags") or []
        ))
    return rules

def field_match(event: Dict[str,Any], when: Dict[str,Any]) -> bool:
    for cond in when if isinstance(when,list) else [when]:
        fld = cond.get("field"); 
        if not fld: continue
        val = event
        for part in fld.split("."):
            if isinstance(val, dict) and part in val: val = val[part]
            else: val=None; break
        if "equals" in cond and val != cond["equals"]: return False
        if "in" in cond and val not in cond["in"]: return False
        if "contains" in cond and (val is None or cond["contains"] not in str(val)): return False
        if "regex" in cond:
            try:
                if val is None or re.search(cond["regex"], str(val)) is None: return False
            except re.error: return False
    return True

class FlowState:
    def __init__(self):
        self.syn_window = defaultdict(lambda: deque())
        self.dst_fanout = defaultdict(lambda: defaultdict(int))
        self.window_events = defaultdict(lambda: deque())
    def _decay(self, dq, window_s):
        boundary = now_ts() - timedelta(seconds=window_s)
        while dq and dq[0] < boundary: dq.popleft()
    def record_syn(self, src_ip, dst_ip, window_s=10):
        dq = self.syn_window[src_ip]; dq.append(now_ts()); self._decay(dq, window_s)
        self.dst_fanout[src_ip][dst_ip] += 1
        return len(dq), len(self.dst_fanout[src_ip])
    def record_generic(self, key: str, window_s=10):
        dq = self.window_events[key]; dq.append(now_ts()); self._decay(dq, window_s)
        return len(dq)
EOF

# cli.py (entrypoint)
cat > "$PROJECT/src/monitorlite/cli.py" <<'EOF'
import argparse, signal, sys
from .decoder import decode
from .logger import AlertSink
from .detection import load_rules, field_match, FlowState
from .capture import live_sniff, pcap_iter

def parse_args():
    ap = argparse.ArgumentParser("monitorlite")
    ap.add_argument("--iface", help="Interface for live capture (sudo likely required)")
    ap.add_argument("--pcap", help="Read packets from pcap file instead of live capture")
    ap.add_argument("--bpf", default="ip", help="BPF filter (default: ip)")
    ap.add_argument("--rules", required=True, help="YAML rules file")
    ap.add_argument("--eve", default="./logs/eve.json", help="EVE JSON output path")
    ap.add_argument("--quiet", action="store_true", help="Disable colored console alerts")
    return ap.parse_args()

def runner(args):
    rules = [r for r in load_rules(args.rules) if r.enabled]
    sink = AlertSink(eve_path=args.eve, pretty_console=not args.quiet)
    flows = FlowState()

    def handle(pkt):
        e = decode(pkt)
        for r in rules:
            if r.when and not field_match({**e, "http": e.get("http") or {}}, r.when):
                continue
            alert = None
            flow = r.flow or {}
            # Stateful detections
            if flow.get("type") == "syn_scan":
                if e.get("l4")=="tcp" and "S" in (e.get("flags") or []) and "A" not in (e.get("flags") or []):
                    n, fan = flows.record_syn(e.get("src_ip"), e.get("dst_ip"), window_s=flow.get("window_s",10))
                    if n>=flow.get("min_syn",30) and fan>=flow.get("min_unique_dst",15):
                        alert = {"category":"scan","src_ip":e.get("src_ip"),"syn_count":n,"unique_dst":fan}
            elif flow.get("type") == "rate_threshold":
                key = str(e.get(flow.get("key_field","src_ip")))
                if key!="None":
                    n = flows.record_generic(key, window_s=flow.get("window_s",5))
                    if n>=flow.get("min_count",400):
                        alert = {"category":"threshold","key":key,"count":n}
            # Stateless rule-only alert
            if (not r.flow and r.when) or alert:
                sink.emit({
                    "rule_id": r.id, "rule": r.title, "severity": r.severity,
                    **(alert or {}),
                    "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
                    "proto": e.get("l4"), "dst_port": e.get("dst_port"),
                    "dns_qname": e.get("dns_qname"), "http": e.get("http")
                })

    def _stop(*_): sink.close(); sys.exit(0)
    signal.signal(signal.SIGINT, _stop)

    if args.pcap:
        for pkt in pcap_iter(args.pcap): handle(pkt)
    else:
        if not args.iface:
            print("ERROR: provide --iface for live capture or --pcap for offline"); sys.exit(2)
        live_sniff(args.iface, args.bpf, handle)

def main():
    runner(parse_args())

if __name__ == "__main__":
    main()
EOF

# allow `python -m monitorlite`
cat > "$PROJECT/src/monitorlite/__main__.py" <<'EOF'
from .cli import main
if __name__ == "__main__":
    main()
EOF

# -------------------- rules & pcaps --------------------
cat > "$PROJECT/rules/example-basic.yml" <<'EOF'
# Port policy
- id: R1001
  title: "Blocklist destination port"
  severity: medium
  when: { field: dst_port, in: [23,2323,5900] }
  enabled: true
  tags: [policy]

# HTTP keyword pattern (payload only)
- id: R1002
  title: "HTTP keyword match (password leak)"
  severity: high
  when: { field: payload, regex: "(?i)password=|passwd=|pwd=" }
  enabled: true
  tags: [dpi,http]

# SYN scan burst (stateful)
- id: R2001
  title: "SYN scan burst"
  severity: high
  when: { field: l4, equals: tcp }
  flow: { type: syn_scan, window_s: 10, min_syn: 30, min_unique_dst: 15 }
  enabled: true
  tags: [scan]

# DoS threshold per source (lab demo)
- id: R5001
  title: "High packet rate from single source"
  severity: high
  when: { field: l3, equals: ipv4 }
  flow: { type: rate_threshold, key_field: src_ip, window_s: 5, min_count: 400 }
  enabled: true
  tags: [dos,threshold]
EOF

cat > "$PROJECT/pcaps/make_sample_pcap.py" <<'EOF'
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap, Raw
pkts = []
dns_q = Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=12345,dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com"))
dns_a = Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53,dport=12345)/DNS(id=dns_q[DNS].id,qr=1,aa=1,qd=dns_q[DNS].qd,an=DNSRR(rrname="example.com",ttl=300,rdata="93.184.216.34"))
http_get = Ether()/IP(src="192.168.1.20", dst="93.184.216.34")/TCP(sport=44444,dport=80,flags="PA")/Raw(
    b"GET /login?user=admin&password=1234 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
http_ok  = Ether()/IP(src="93.184.216.34", dst="192.168.1.20")/TCP(sport=80,dport=44444,flags="PA")/Raw(
    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
pkts += [dns_q, dns_a, http_get, http_ok]
wrpcap("pcaps/sample.pcap", pkts)
print("✅ pcaps/sample.pcap written with", len(pkts), "packets")
EOF

# -------------------- optional lab traffic tool --------------------
cat > "$PROJECT/tools/traffic_gen.py" <<'EOF'
# LAB-ONLY traffic generator (raw packets). Run with sudo.
import argparse, time
from scapy.all import IP, TCP, UDP, Ether, sendp, Raw
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--proto", choices=["tcp","udp"], default="tcp")
    p.add_argument("--syn", action="store_true")
    p.add_argument("--pps", type=int, default=1000)
    p.add_argument("--seconds", type=int, default=5)
    p.add_argument("--iface", default=None)
    a = p.parse_args()
    pkt = IP(dst=a.target)
    if a.proto=="tcp":
        flags = "S" if a.syn else "PA"
        pkt /= TCP(dport=a.port, sport=55555, flags=flags) / Raw(b"X"*32)
    else:
        pkt /= UDP(dport=a.port, sport=55555) / Raw(b"X"*32)
    frame = Ether()/pkt
    interval = 1.0/max(a.pps,1); end = time.time()+a.seconds
    print(f"Sending ~{a.pps} pps for {a.seconds}s to {a.target}:{a.port} ({a.proto})")
    while time.time()<end:
        sendp(frame, iface=a.iface, verbose=False); time.sleep(interval)
    print("Done.")
if __name__=="__main__": main()
EOF

# -------------------- create sample pcap + zip --------------------
python3 - <<'PY'
import subprocess, sys
subprocess.run([sys.executable, "pcaps/make_sample_pcap.py"], cwd="monitorlite", check=True)
PY

( cd "$PROJECT" && zip -r ../monitorlite.zip . >/dev/null )
echo "✅ Created project folder: $PROJECT"
echo "✅ Created archive: monitorlite.zip"
