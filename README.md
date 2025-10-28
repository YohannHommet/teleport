# 🚀 Teleport

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Bun](https://img.shields.io/badge/Bun-1.0+-black)](https://bun.sh)
[![Version](https://img.shields.io/badge/Version-3.0.0-green)](#)

Zero‑config, fast, secure LAN file transfer. Teleport uses UDP multicast discovery and a direct TCP one‑shot transfer.

## ⚡ Features

- 🔐 AES‑256‑GCM encryption when a PSK is provided
- Zero configuration via UDP multicast discovery (TTL=1, LAN only)
- One‑shot transfer (sender exits after first successful download)
- HMAC‑SHA256 signed beacons (anti‑tamper, anti‑replay window)
- SHA‑256 integrity verification after download
- Path traversal protection, size validation, timeouts, DoS guard
- Realtime progress: throughput and ETA
- 80–120 MB/s on gigabit; large files 50GB+ via streaming
- Cross‑platform: Linux, macOS, Windows (Bun runtime)

## 📦 Install

Prerequisite: [Bun 1.0+](https://bun.sh)

```bash
git clone https://github.com/yourusername/teleport.git
cd teleport
bun teleport.ts --help
```

## 🎯 Quick Start

### 1) Simple transfer (unencrypted)

On the receiver:
```bash
bun teleport.ts
```
On the sender:
```bash
bun teleport.ts send presentation.pdf
```
The file is automatically discovered; the receiver saves it as `<id>-presentation.pdf`.

---

### 2) Secure transfer (AES‑256‑GCM with PSK)

Generate a strong PSK (once):
```bash
openssl rand -hex 32 > ~/.teleport-key
chmod 600 ~/.teleport-key
```
Receiver (PSK required):
```bash
bun teleport.ts --psk $(cat ~/.teleport-key)
```
Sender (same PSK):
```bash
bun teleport.ts send confidential.zip --psk $(cat ~/.teleport-key)
```
Only receivers with the correct PSK will accept and decrypt.

---

### 3) Large files (GBs)
Receiver:
```bash
mkdir -p ~/Downloads/teleport
bun teleport.ts --dir ~/Downloads/teleport --psk mykey
```
Sender:
```bash
bun teleport.ts send ubuntu-server.iso --psk mykey
```
Results:
- ✅ SHA‑256 verified automatically
- ✅ 80–120 MB/s on gigabit
- ✅ Streaming supports 50GB+ files

---

### 4) Pick a network interface
List interfaces:
```bash
ip addr show  # Linux
ifconfig      # macOS
```
Use a specific interface:
```bash
# By interface name
bun teleport.ts send file.zip --iface eth0

# By IP
bun teleport.ts send file.zip --iface 192.168.1.100
```

---

### 5) Custom download directory
```bash
bun teleport.ts --dir ./incoming --psk secret123
```

---

### 6) Advanced example
Receiver:
```bash
bun teleport.ts \
  --psk $(cat ~/.teleport-key) \
  --dir ~/secure-downloads \
  --maxsize 10737418240 \
  --iface eth0
```
Sender:
```bash
bun teleport.ts send archive.tar.gz \
  --psk $(cat ~/.teleport-key) \
  --iface eth0 \
  --name "Backup-2025-09-29"
```

## 🔧 CLI Options

- `--psk <secret>`: Pre‑shared key. Enables AES‑256‑GCM encryption and HMAC auth.
- `--dir <path>`: Output directory (receiver).
- `--maxsize <bytes>`: Maximum allowed file size (default: 10GB).
- `--iface <name|ip>`: Network interface or IP to bind.
- `--name <display>`: Custom display name for the sender.

## 🔒 Security

Implemented:
- HMAC‑SHA256 authentication (optional PSK)
- AES‑256‑GCM encryption (active when PSK provided)
- SHA‑256 integrity verification
- Path traversal protection; sanitized filenames
- Timeouts, size limits, DoS guard (max concurrent downloads)
- Anti‑replay (timestamp window)
- LAN‑only by default (multicast TTL=1)
- One‑shot sender lifecycle

Notes:
- Encryption is on only if `--psk` is set.
- Beacons are HMAC‑signed over stable fields: `v|id|name|size|port|ip|timestamp|hash`.
- For untrusted networks, use a VPN over Teleport.

## 🌐 Networking

Defaults:
- Multicast address: `239.255.0.42`
- Discovery port: `5042/UDP`
- Transfer port: ephemeral `TCP`
- Scope: LAN only (TTL=1)

Firewall quick tips:
- Linux (ufw): `sudo ufw allow 5042/udp`
- Windows: allow UDP 5042 in Defender Firewall
- macOS: allow when prompted

WSL2 multicast routing:
```bash
sudo ip route add 239.0.0.0/8 dev eth0
```

## 🏗️ Architecture

Two‑phase protocol:
1) UDP multicast discovery (beacons every 500ms)
2) Direct TCP transfer (streaming, one‑shot)

Beacon fields (v3): `v, id, name, size, port, ip, timestamp, hash, sig`

## ✅ Testing

Quick test:
```bash
# Receiver
bun teleport.ts --psk test123 > teleport-receiver.log 2>&1

# Sender
echo "hello" > test.txt
bun teleport.ts send test.txt --psk test123
```

What to expect:
- Receiver prints progress, then “Download complete” and “Hash verified successfully”.

## 🐛 Troubleshooting (quick)

- UDP error EADDRINUSE → Port 5042 in use. Stop previous runs: `pkill -f "bun.*teleport"`.
- No files discovered → Open UDP 5042 in firewall; ensure same subnet; on WSL2 add multicast route.
- addMembership failed → Use `--iface` to select a supported NIC.
- Slow transfer → Prefer wired, close bandwidth‑heavy apps, check packet loss, test with `iperf3`.
- Security block → Filenames are sanitized. If needed, rename locally before sending.

## 🚀 Performance

- Gigabit Ethernet: 80–120 MB/s
- Wi‑Fi 5: 30–60 MB/s
- Discovery latency: < 500ms
- Memory: ~50MB (streaming)

## 📝 License

Apache License 2.0

## 🙏 Acknowledgements

- Built with [Bun](https://bun.sh)
- Inspired by classic LAN sharing tools

---

## 🗺️ Roadmap

- [ ] Resume interrupted transfers
- [ ] Directory transfers
- [ ] Optional compression
- [ ] GUI

---

Version: 1.0.0 · Status: ✅ Ready  
Tested: 16 bytes → 50GB+ · Performance: 80–120 MB/s (gigabit)

--- 

Provided and developed by [Yohann Hommet](https://github.com/YohannHommet)