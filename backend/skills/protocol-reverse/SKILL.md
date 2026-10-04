---
name: protocol-reverse
description: "Network protocol / traffic reverse engineering: PCAP capture and dissection (Wireshark/tshark/tcpdump), HTTP(S) request replay, protobuf/.proto schema recovery, gRPC reflection and binary-protocol parsing. Use for analyzing app traffic, custom protocols, mobile/web API handshakes and replaying captured requests during authorized engagements."
category: reverse
allowed_tools:
  - wireshark
  - tshark
  - tcpdump
  - tcpflow
  - protoc
  - grpcurl
  - curl
  - mitmproxy
  - python3
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Protocol Reverse Methodology

## 1. Capture
- `tcpdump -i any -w cap.pcap host <target>` (authorized scope only)
- `tshark -r cap.pcap -Y http -T fields -e http.request.full_uri` for quick triage
- Load in Wireshark; apply `http2` / `tls` decode keys if provided

## 2. HTTP(S) replay
- Export request: `tshark -Y "tcp.stream eq N" -T fields -e http.request.line -e data.data`
- Replay with `curl` (headers + body); document responses (screenshots/PoC)
- Check auth coupling: tokens, Req-ID, signed params → ties into js-reverse workflow

## 3. protobuf / gRPC
- Detect: `tshark -r cap.pcap -Y grpc`; `.proto` recovery → `protoc --decode_raw`
- Use reflection: `grpcurl -plaintext -protoset-out x.protoset <host>:<port> list`
- Field-map unknown numbers via `--decode_raw` dumps + heuristics

## 4. Binary/custom protocols
- Find magic/length framing; use Python `construct`/`kaitai` for parsing
- Differential: change one client behavior → diff two captures (fields reveal meaning)

## 5. Findings
- Pivot captured endpoints into Burp Bridge / Browser Capture for findings
- Attach evidence: stream index, decrypted payload excerpt, replay command