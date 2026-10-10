---
name: wireless-audit
description: "Documented audit plan for Wi-Fi security using aircrack-ng suite (host-based). Guide only: plan, commands, OPSEC, legal, handoff. Do NOT assume Docker access to wireless card/monitor mode. Use on authorized Kali physical host."
category: recon
allowed_tools:
  - nmap
  - curl
  - python3
version: "1.0.0"
author: "MIRV (reference: airgorah)"
license: "MIT"
---

# Wireless Audit (aircrack-ng flow) — Reference-only

This is documentation-only. MIRV cannot run monitor mode from Docker. Steps require direct access to Wi-Fi adapter on a Kali Linux host.

## LEGAL / OPSEC (MANDATORY)
- Only audit networks you own or are explicitly authorized to test.
- Never attack third-party networks.
- Enforce scope (authorized BSSID/ESSID/channel). Redact PCAPs before sharing.

## Hardware checks (Kali host)
```bash
iw dev
airmon-ng
```

## 1) Monitor mode
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iwconfig  # Mode:Monitor
```

## 2) Discovery
```bash
sudo airodump-ng wlan0mon --write capture
# record BSSID, CH, ENC, PWR, ESSID
```

## 3) Targeted capture
```bash
sudo airodump-ng --bssid <BSSID> -c <CH> --write handshake wlan0mon
```

## 4) Deauth (AUTHORIZED ONLY)
```bash
sudo aireplay-ng --deauth 4 -a <BSSID> -c <STA> wlan0mon
```

## 5) Crack
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-*.cap
```

## Handoff
- Stop: `sudo airmon-ng stop wlan0mon && sudo service NetworkManager start`
- Evidence hash (sha256 of cap), scope satisfied, no extra deauths.
- GUI alternative: [airgorah](https://github.com/martin-olivier/airgorah) (Linux host).

## MIRV notes
- `wireless_analyzer.py` wraps via SSH (paramiko) to physical Kali host (`MIRV_WIRELESS_*`).
- Endpoints: `POST/GET /api/wireless/*` (start/stop/status, deauth, crack, artifacts).
- Tab `Wireless` host-only; Docker unsupported → UI disabled unless host configured.
