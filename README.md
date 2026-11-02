<div align="center">

```
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠛⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⢁⠆⢻⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⡿⢻⣿
⡇⠆⡘⢿⣿⣿⡿⢈⢻⣿⣿⣿⠇⣤⡏⡄⢿⣿⣿⣿⢃⠘⣿⣿⣿⡟⠐⡌⣿
⠃⢠⣆⠌⢿⣿⠇⣻⢊⢻⣿⡟⢨⢺⡷⢸⠈⣿⣿⢃⢰⡄⣿⣿⠏⣐⣴⠠⢹
⠘⡘⣿⣹⢸⣿⣀⢻⡞⣨⣿⣶⢀⣣⣥⣇⢲⣿⣧⡘⡮⢃⣸⣧⢸⡼⡟⡠⢸
⣧⠈⣦⢻⠸⣿⣿⠈⣧⢈⠻⠏⣼⣻⢟⣿⡌⠿⢋⢠⢡⢸⣿⡿⢸⢣⡞⢀⣿
⣿⡄⠺⣼⣇⠙⣣⣺⣿⡷⢉⣼⣻⣿⣾⣿⣻⣄⠱⣿⣎⢤⡛⢃⣾⡵⠂⣸⣿
⣿⣧⠐⣽⣿⣷⣦⣭⢥⣶⣿⣿⣿⣿⣿⣿⣿⣿⣳⣦⡭⣤⣴⣿⣿⠽⠀⣿⣿
⣿⣿⠀⠛⣻⡭⣿⣿⣿⣯⣯⣽⣿⣿⡿⣿⣿⣿⣭⣵⣎⣶⡮⣽⡋⠃⢀⣿⣿
⣿⣿⠀⢸⣽⣴⣽⣿⣿⣿⣿⡿⠿⠷⠿⠾⠿⠿⣿⣿⣿⣿⣝⣽⣿⠀⢸⣿⣿
⡿⠟⠀⢀⣀⠀⠀⢀⣀⠀⣀⡀⠀⣀⠀⠀⠀⣀⠀⠀⠀⠀⣀⣀⠀⠀⢘⢿⣿
⣷⣤⡄⢘⣿⠇⣠⡿⠋⠀⣿⡇⠀⣿⣧⡀⠀⣿⠀⢠⣾⠛⠉⠋⠁⠀⣤⣴⣿
⣿⣿⡇⢨⣿⡿⣿⢄⠀⠀⣿⠆⠀⡇⠹⣷⡄⣿⠀⣿⡇⠀⠀⢠⣤⠀⣿⣿⣿
⣿⣿⡇⢸⣿⡅⠘⢿⣦⠀⣿⡇⠀⣷⠀⠈⢿⣿⠀⠹⣷⣄⣀⣸⣿⠀⣿⣿⣿
⣿⣿⣧⣈⣟⣇⣀⣨⣉⣅⣭⣃⣤⣭⣄⣤⣤⣩⣥⣤⣤⣭⣭⣭⣭⣤⣿⣿⣿
```

# M A T R I X   N E T   W A T C H

**A Matrix-style live network monitor and anomaly watcher for your own machine.**

*Coded by Mr Sabaz Ali Khan*

![Python](https://img.shields.io/badge/Python-3.7%2B-green?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-brightgreen)
![Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20(psutil%20optional)-blue)
![Purpose](https://img.shields.io/badge/Purpose-Defensive-success)

</div>

---

## Overview

**MatrixNetWatch** is a lightweight, single-file terminal dashboard that continuously watches your system's network activity and raises alerts when something looks off. It opens with a Matrix digital-rain intro and then shows a live, color-coded dashboard of connections, traffic, top remote hosts, and security alerts.

It is built for **defenders**: blue teamers, sysadmins, security students, and anyone who wants quick visibility into what their own machine is doing on the network.

> **Legal notice:** Use this tool only on systems and networks you own or are explicitly authorized to monitor.

---

## Features

| Detection | Description | Severity |
|---|---|---|
| **New listening ports** | Flags any new TCP/UDP listener that appears after the baseline (possible backdoor or unexpected service) | `HIGH` |
| **Port-scan behavior** | One remote IP touching many of your local ports within a time window | `HIGH` |
| **ARP table changes** | An IP's MAC address changes (possible ARP spoofing / MITM). *Linux only* | `HIGH` |
| **Suspicious outbound ports** | New connections to commonly abused ports (e.g. 4444, 6667, 31337, 12345, 1337) | `WARN` |
| **Connection floods** | A single external IP holding many simultaneous connections | `WARN` |
| **Bandwidth spikes** | Per-interface traffic exceeding a configurable MB/s threshold | `WARN` |
| **New external connections** | Every new connection to a public IP (verbose mode) | `INFO` |

**Other highlights**

- Live dashboard: status bar, per-interface traffic (↓ / ↑), top remote hosts, and a rolling alert feed
- Automatic **baseline** scan on startup so existing connections don't trigger false alarms
- Alert **cooldowns** to avoid log spam
- Structured **JSON-lines logging** for easy ingestion into other tools
- Optional terminal bell on `HIGH` / `WARN` alerts
- **Zero required dependencies** (uses `/proc` on Linux); installs `psutil` for richer data and cross-platform support
- Single file, easy to read and extend

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/whoami592/matrix_net_watch.git
cd MatrixNetWatch

# 2. (Recommended) install psutil for process names and cross-platform support
pip install psutil
```

**Requirements**

- Python 3.7 or newer
- `psutil` *(optional on Linux, required on Windows/macOS for connection and traffic data)*

---

## Usage

```bash
# Basic run (use root/sudo on Linux to see process names and all sockets)
sudo python3 matrixnetwatch.py

# Skip the intro animation and use the compact dashboard
python3 matrixnetwatch.py --no-intro --compact

# Verbose mode: report every new external connection
python3 matrixnetwatch.py -v

# Faster refresh, stricter scan detection, with audible alerts
python3 matrixnetwatch.py -i 1 --scan-threshold 5 --bell

# Write alerts to a custom log file
python3 matrixnetwatch.py -l alerts.jsonl
```

Press **Ctrl+C** to exit.

### Command-line options

| Option | Default | Description |
|---|---|---|
| `-i`, `--interval` | `2.0` | Dashboard refresh interval in seconds |
| `-w`, `--window` | `60` | Time window (seconds) used for port-scan detection |
| `--scan-threshold` | `10` | Distinct local ports from one IP that count as a scan |
| `--flood-threshold` | `50` | Simultaneous connections from one IP that count as a flood |
| `--bw-threshold` | `20.0` | Bandwidth spike alert threshold in MB/s |
| `--include-private` | off | Also track LAN (private) IPs for scan detection |
| `-v`, `--verbose` | off | Report every new external connection as `INFO` |
| `-l`, `--log` | `matrixnetwatch.log` | JSON-lines log file (pass `''` to disable) |
| `--no-intro` | off | Skip the Matrix rain intro |
| `--compact` | off | Hide the large banner on the dashboard |
| `--bell` | off | Terminal bell on `HIGH` / `WARN` alerts |

---

## Log format

Alerts are written as one JSON object per line:

```json
{"time": "2026-11-02T14:05:31.482913", "level": "HIGH", "type": "PORT_SCAN", "msg": "203.0.113.7 probed 12 local ports in 60s"}
```

Alert types: `NEW_LISTENER`, `PORT_SCAN`, `ARP_CHANGE`, `SUSPICIOUS_PORT`, `CONN_FLOOD`, `BANDWIDTH`, `NEW_CONN`.

---

## How it works

1. **Baseline:** two quick scans on startup record existing listeners, connections, and ARP entries.
2. **Monitoring loop:** every refresh interval, the tool re-reads the connection table (via `psutil` or `/proc/net/*`), interface counters, and the ARP table.
3. **Detection:** new listeners, scan/flood heuristics, suspicious ports, MAC changes, and bandwidth deltas are compared against the baseline and thresholds.
4. **Output:** alerts appear on the dashboard, in the optional log file, and (optionally) as a terminal bell.

---

## Platform notes

- **Linux:** full feature set, including ARP spoofing detection. Run as root for process names and complete socket visibility.
- **Windows / macOS:** requires `psutil`. ARP change detection relies on `/proc/net/arp` and is therefore Linux-only. On Windows 10+, ANSI colors are enabled automatically.
- Detection of suspicious ports is **heuristic only**. A hit is a lead to investigate, not proof of compromise.

---

## Limitations

- Not a replacement for a full IDS/IPS (Snort, Suricata, Zeek).
- Monitors the local host's view of the network only; it does not capture packets.
- Heuristic thresholds may need tuning for busy servers to reduce false positives.

---

## Disclaimer

This project is provided for **educational and defensive security purposes only**. The author is not responsible for misuse. Always obtain proper authorization before monitoring any system or network.

---

## Author

**Coded by Mr Sabaz Ali Khan**
Cyber Security Engineer

---

## License

Released under the [MIT License](LICENSE). Add a `LICENSE` file to your repository to match.

---

<div align="center">

*Stay ethical. Watch the matrix.*

</div>
