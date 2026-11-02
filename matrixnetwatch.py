#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MatrixNetWatch - Matrix-style live network monitor & anomaly watcher.
Coded by Ethical Hacker Mr Hasnain

Monitors YOUR OWN machine/network for:
  * New listening ports (possible backdoor / unexpected service)
  * New outbound connections, flagged on commonly abused ports
  * Port-scan behaviour (one remote IP touching many local ports)
  * Connection floods from a single remote IP
  * ARP table changes (possible ARP spoofing / MITM)  [Linux]
  * Bandwidth spikes per interface

Works with stdlib only (Linux /proc fallback); installs better with: pip install psutil
Use only on systems/networks you own or are authorized to monitor.
"""

import argparse
import ipaddress
import json
import os
import random
import shutil
import socket
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

# ----------------------------------------------------------------- colours
G = "\033[92m"; DG = "\033[32m"; R = "\033[91m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; B = "\033[1m"; X = "\033[0m"

BANNER = r"""⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
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
⣿⣿⣧⣈⣟⣇⣀⣨⣉⣅⣭⣃⣤⣭⣄⣤⣤⣩⣥⣤⣤⣭⣭⣭⣭⣤⣿⣿⣿"""

TITLE = "M A T R I X   N E T   W A T C H"
CREDIT = "Coded by Ethical Hacker Mr Hasnain"

# Ports commonly used by backdoors / C2 / RATs / IRC bots (heuristic only)
SUSPICIOUS_PORTS = {
    1337: "leet/backdoor", 4444: "metasploit default", 5555: "adb/RAT",
    6666: "IRC/backdoor", 6667: "IRC (botnet C2)", 31337: "Back Orifice",
    12345: "NetBus", 9001: "Tor ORPort", 9050: "Tor SOCKS", 2222: "alt SSH",
    8888: "alt shell/proxy", 1080: "SOCKS proxy", 3389: "RDP",
}

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


# ----------------------------------------------------------------- data collection
def _hex_ip(h):
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return socket.inet_ntoa(raw[::-1])
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, raw)


def _proc_net(path, proto):
    out = []
    try:
        with open(path) as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) < 4:
                    continue
                lip, lport = p[1].split(":")
                rip, rport = p[2].split(":")
                state = TCP_STATES.get(p[3], p[3]) if proto == "tcp" else (
                    "LISTEN" if int(rport, 16) == 0 else "ESTABLISHED")
                out.append({
                    "proto": proto, "laddr": _hex_ip(lip), "lport": int(lport, 16),
                    "raddr": _hex_ip(rip), "rport": int(rport, 16),
                    "state": state, "pid": None, "proc": "-",
                })
    except (OSError, ValueError, StopIteration):
        pass
    return out


def get_connections():
    if psutil:
        out = []
        try:
            for c in psutil.net_connections(kind="inet"):
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                la, lp = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
                ra, rp = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
                state = c.status if proto == "tcp" else ("LISTEN" if not ra else "ESTABLISHED")
                name = "-"
                if c.pid:
                    try:
                        name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                out.append({"proto": proto, "laddr": la, "lport": lp, "raddr": ra,
                            "rport": rp, "state": state, "pid": c.pid, "proc": name})
            return out
        except (psutil.AccessDenied, PermissionError):
            pass  # fall through to /proc
    conns = []
    for path, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"),
                        ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp")):
        conns += _proc_net(path, proto)
    return conns


def get_io():
    if psutil:
        return {k: (v.bytes_recv, v.bytes_sent) for k, v in psutil.net_io_counters(pernic=True).items()}
    io = {}
    try:
        with open("/proc/net/dev") as f:
            for line in list(f)[2:]:
                name, data = line.split(":", 1)
                d = data.split()
                io[name.strip()] = (int(d[0]), int(d[8]))
    except OSError:
        pass
    return io


def get_arp():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3].lower()
    except (OSError, StopIteration):
        pass
    return table


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return True


# ----------------------------------------------------------------- watcher
class MatrixNetWatch:
    def __init__(self, args):
        self.a = args
        self.alerts = deque(maxlen=14)
        self.counts = defaultdict(int)
        self.known_listen = set()
        self.known_conns = set()
        self.arp = {}
        self.io_prev = {}
        self.io_rate = {}
        self.scan_track = defaultdict(deque)   # ip -> deque[(ts, lport)]
        self.cooldown = {}
        self.t_prev = time.time()
        self.started = time.time()
        self.logf = open(args.log, "a", encoding="utf-8") if args.log else None

    # -- alerting
    def alert(self, level, kind, msg, key=None, cooldown=120):
        now = time.time()
        k = key or (kind, msg)
        if now - self.cooldown.get(k, 0) < cooldown:
            return
        self.cooldown[k] = now
        ts = datetime.now().strftime("%H:%M:%S")
        self.alerts.appendleft((ts, level, kind, msg))
        self.counts[level] += 1
        if self.logf:
            self.logf.write(json.dumps({"time": datetime.now().isoformat(), "level": level,
                                        "type": kind, "msg": msg}) + "\n")
            self.logf.flush()
        if self.a.bell and level in ("HIGH", "WARN"):
            sys.stdout.write("\a")

    # -- one scan cycle
    def scan(self, baseline=False):
        conns = get_connections()
        now = time.time()
        listeners = {(c["proto"], c["lport"]) for c in conns if c["state"] == "LISTEN"}
        per_remote = defaultdict(int)
        current = set()

        for c in conns:
            if c["state"] == "LISTEN" or not c["raddr"]:
                continue
            key = (c["proto"], c["laddr"], c["lport"], c["raddr"], c["rport"])
            current.add(key)
            if c["state"] in ("ESTABLISHED", "SYN_RECV", "SYN_SENT"):
                per_remote[c["raddr"]] += 1

            # port-scan tracking: remote touching our listening/local ports
            if (c["proto"], c["lport"]) in listeners or c["state"] == "SYN_RECV":
                if not is_private(c["raddr"]) or self.a.include_private:
                    dq = self.scan_track[c["raddr"]]
                    dq.append((now, c["lport"]))

            if baseline or key in self.known_conns:
                continue
            label = f'{c["proc"]}({c["pid"]}) ' if c["pid"] else ""
            desc = f'{c["proto"].upper()} {label}{c["laddr"]}:{c["lport"]} -> {c["raddr"]}:{c["rport"]}'
            if c["rport"] in SUSPICIOUS_PORTS:
                self.alert("WARN", "SUSPICIOUS_PORT",
                           f'{desc}  [{SUSPICIOUS_PORTS[c["rport"]]}]')
            elif self.a.verbose and not is_private(c["raddr"]):
                self.alert("INFO", "NEW_CONN", desc, key=("conn",) + key, cooldown=30)

        if not baseline:
            for proto, port in sorted(listeners - self.known_listen):
                self.alert("HIGH", "NEW_LISTENER", f"New {proto.upper()} listener on port {port}",
                           key=("listen", proto, port), cooldown=600)
        self.known_listen |= listeners
        self.known_conns = current

        # scan / flood heuristics
        window = self.a.window
        for ip, dq in list(self.scan_track.items()):
            while dq and now - dq[0][0] > window:
                dq.popleft()
            if not dq:
                del self.scan_track[ip]
                continue
            ports = {p for _, p in dq}
            if len(ports) >= self.a.scan_threshold and not baseline:
                self.alert("HIGH", "PORT_SCAN",
                           f"{ip} probed {len(ports)} local ports in {window}s",
                           key=("scan", ip))
        for ip, n in per_remote.items():
            if n >= self.a.flood_threshold and not baseline and not is_private(ip):
                self.alert("WARN", "CONN_FLOOD", f"{ip} holds {n} simultaneous connections",
                           key=("flood", ip))

        self.top = sorted(per_remote.items(), key=lambda x: -x[1])[:5]
        self.n_conns = len(current)
        self.n_listen = len(listeners)

        # ARP spoof detection
        arp = get_arp()
        if self.arp and not baseline:
            for ip, mac in arp.items():
                old = self.arp.get(ip)
                if old and old != mac:
                    self.alert("HIGH", "ARP_CHANGE",
                               f"{ip} changed MAC {old} -> {mac} (possible ARP spoofing)",
                               key=("arp", ip, mac), cooldown=300)
        self.arp.update(arp)

        # bandwidth
        io = get_io()
        dt = max(now - self.t_prev, 0.001)
        for nic, (rx, tx) in io.items():
            if nic in self.io_prev:
                prx, ptx = self.io_prev[nic]
                self.io_rate[nic] = ((rx - prx) / dt, (tx - ptx) / dt)
                mb = max(self.io_rate[nic]) / 1e6
                if mb >= self.a.bw_threshold and not baseline and nic != "lo":
                    self.alert("WARN", "BANDWIDTH", f"{nic} at {mb:.1f} MB/s", key=("bw", nic), cooldown=60)
        self.io_prev = io
        self.t_prev = now

    # -- UI
    @staticmethod
    def _fmt(bps):
        for u in ("B/s", "KB/s", "MB/s", "GB/s"):
            if bps < 1024:
                return f"{bps:6.1f} {u}"
            bps /= 1024
        return f"{bps:.1f} TB/s"

    def render(self):
        cols = shutil.get_terminal_size((100, 30)).columns
        up = int(time.time() - self.started)
        lvl = {"HIGH": R, "WARN": Y, "INFO": C}
        out = ["\033[H\033[J"]
        if not self.a.compact:
            out.append(G + BANNER + X)
        out.append(f"{B}{G}{TITLE.center(min(cols, 60))}{X}")
        out.append(f"{DG}{CREDIT.center(min(cols, 60))}{X}\n")
        out.append(f"{G}[ STATUS ]{X} {W}conns:{self.n_conns}  listeners:{self.n_listen}  "
                   f"uptime:{up//60}m{up%60:02d}s  "
                   f"{R}HIGH:{self.counts['HIGH']}{X} {Y}WARN:{self.counts['WARN']}{X} "
                   f"{C}INFO:{self.counts['INFO']}{X}  {DIM}engine:{'psutil' if psutil else '/proc'}{X}")
        out.append(f"{G}[ TRAFFIC ]{X}")
        for nic, (rx, tx) in list(self.io_rate.items())[:5]:
            out.append(f"  {DG}{nic:<10}{X} ↓ {self._fmt(rx)}   ↑ {self._fmt(tx)}")
        out.append(f"{G}[ TOP REMOTES ]{X}")
        for ip, n in self.top or [("-", 0)]:
            out.append(f"  {DG}{ip:<40}{X} {n}")
        out.append(f"{G}[ ALERTS ]{X}")
        if not self.alerts:
            out.append(f"  {DIM}All quiet... watching the matrix.{X}")
        for ts, level, kind, msg in self.alerts:
            line = f"  {DIM}{ts}{X} {lvl.get(level, W)}{level:<4} {kind:<16}{X} {msg}"
            out.append(line[: cols + 30])
        out.append(f"\n{DIM}Ctrl+C to exit • log: {self.a.log or 'off'}{X}")
        sys.stdout.write("\n".join(out) + "\n")
        sys.stdout.flush()

    def run(self):
        self.scan(baseline=True)
        time.sleep(1)
        self.scan(baseline=True)
        while True:
            self.scan()
            self.render()
            time.sleep(self.a.interval)


# ----------------------------------------------------------------- matrix intro
def matrix_rain(seconds=3.0):
    cols, rows = shutil.get_terminal_size((100, 30))
    chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾅﾆﾇﾈ0123456789ABCDEF$#@%&"
    drops = [random.randint(-rows, 0) for _ in range(cols)]
    end = time.time() + seconds
    sys.stdout.write("\033[?25l\033[2J")
    try:
        while time.time() < end:
            buf = []
            for x in range(cols):
                y = drops[x]
                if 0 <= y < rows:
                    buf.append(f"\033[{y+1};{x+1}H{W}{random.choice(chars)}")
                if 0 <= y - 1 < rows:
                    buf.append(f"\033[{y};{x+1}H{G}{random.choice(chars)}")
                if 0 <= y - 6 < rows:
                    buf.append(f"\033[{y-5};{x+1}H{DG}{random.choice(chars)}")
                if 0 <= y - 12 < rows:
                    buf.append(f"\033[{y-11};{x+1}H ")
                drops[x] = y + 1 if y < rows + 12 or random.random() < 0.05 else random.randint(-10, 0)
            sys.stdout.write("".join(buf) + X)
            sys.stdout.flush()
            time.sleep(0.04)
    finally:
        sys.stdout.write("\033[?25h\033[2J\033[H" + X)


def parse_args():
    p = argparse.ArgumentParser(description="MatrixNetWatch - Matrix-style network monitor (defensive).")
    p.add_argument("-i", "--interval", type=float, default=2.0, help="refresh seconds (default 2)")
    p.add_argument("-w", "--window", type=int, default=60, help="scan-detection window seconds")
    p.add_argument("--scan-threshold", type=int, default=10, help="distinct local ports from one IP = scan")
    p.add_argument("--flood-threshold", type=int, default=50, help="connections from one IP = flood")
    p.add_argument("--bw-threshold", type=float, default=20.0, help="MB/s spike alert")
    p.add_argument("--include-private", action="store_true", help="also track LAN IPs for scan detection")
    p.add_argument("-v", "--verbose", action="store_true", help="report every new external connection")
    p.add_argument("-l", "--log", default="matrixnetwatch.log", help="JSON-lines log file ('' to disable)")
    p.add_argument("--no-intro", action="store_true", help="skip matrix rain intro")
    p.add_argument("--compact", action="store_true", help="hide big banner on dashboard")
    p.add_argument("--bell", action="store_true", help="terminal bell on HIGH/WARN")
    return p.parse_args()


def main():
    if os.name == "nt":
        os.system("")  # enable ANSI on Windows 10+
    args = parse_args()
    if not args.no_intro:
        matrix_rain()
    print(G + BANNER + X)
    print(f"{B}{G}{TITLE}{X}\n{DG}{CREDIT}{X}\n")
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{Y}[!] Not root: process names / some sockets may be hidden.{X}")
    print(f"{DG}[*] Building baseline... use only on systems you are authorized to monitor.{X}")
    watcher = MatrixNetWatch(args)
    try:
        watcher.run()
    except KeyboardInterrupt:
        print(f"\n{G}[+] MatrixNetWatch stopped. Stay ethical. — Mr Hasnain{X}")


if __name__ == "__main__":
    main()
