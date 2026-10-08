#!/usr/bin/env python3
"""Summarise a Wireshark capture with TShark (Python standard library only)."""

import argparse
import collections
import csv
import datetime as dt
import os
import pathlib
import shutil
import subprocess
import sys


FIELDS = [
    "frame.time_epoch", "frame.len", "ip.src", "ipv6.src", "ip.dst",
    "ipv6.dst", "frame.protocols", "dns.qry.name", "dns.flags.response",
    "tcp.analysis.retransmission",
]


def tshark_path():
    installed = shutil.which("tshark")
    if installed:
        return installed
    candidates = [
        pathlib.Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark" / "tshark.exe",
        pathlib.Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Wireshark" / "tshark.exe",
        pathlib.Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
    ]
    return str(next((path for path in candidates if path.is_file()), candidates[0]))


def protocol(stack):
    parts = stack.lower().split(":")
    for name in ("dns", "quic", "tls", "http2", "http", "ssh", "icmpv6", "icmp", "tcp", "udp"):
        if name in parts:
            return name.upper()
    return parts[-1].upper() if parts else "OTHER"


def table(title, rows, labels):
    lines = [f"## {title}", "", "| " + " | ".join(labels) + " |", "| " + " | ".join("---" for _ in labels) + " |"]
    lines += ["| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |" for row in rows]
    if not rows:
        lines.append("| " + " | ".join(["No data"] + [""] * (len(labels) - 1)) + " |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Summarise a .pcap or .pcapng capture")
    parser.add_argument("capture", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("traffic-report.md"))
    args = parser.parse_args()
    if not args.capture.is_file():
        parser.error(f"Capture file not found: {args.capture}")

    command = [tshark_path(), "-r", str(args.capture), "-T", "fields"]
    for field in FIELDS:
        command.extend(["-e", field])
    command.extend(["-E", "separator=/t", "-E", "occurrence=f", "-E", "header=n"])

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        parser.error("TShark not found. Install Wireshark with TShark selected and check the README.")

    protocols = collections.Counter()
    destinations = collections.Counter()
    conversations = collections.Counter()
    domains = collections.Counter()
    minutes = collections.Counter()
    total = retransmissions = 0
    first = last = None
    for row in csv.reader(process.stdout, delimiter="\t"):
        if len(row) != len(FIELDS):
            continue
        time, size, ip4src, ip6src, ip4dst, ip6dst, stack, domain, dns_response, retransmit = row
        try:
            timestamp, length = float(time), int(size)
        except ValueError:
            continue
        total += 1
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        protocols[protocol(stack)] += 1
        src, dst = ip4src or ip6src, ip4dst or ip6dst
        if dst:
            destinations[dst] += length
        if src and dst:
            conversations[tuple(sorted((src, dst)))] += length
        if domain and dns_response == "0":
            domains[domain] += 1
        if retransmit:
            retransmissions += 1
        minute = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        minutes[minute] += length

    error = process.stderr.read()
    status = process.wait()
    if status:
        sys.exit(f"TShark failed: {error.strip()}")
    if not total:
        sys.exit("No packets found in the capture.")

    start = dt.datetime.fromtimestamp(first, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    end = dt.datetime.fromtimestamp(last, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections = [
        "# Network traffic report",
        f"Capture: `{args.capture.name}`  ",
        f"Time: {start} to {end}  ",
        f"Packets: {total:,}  ",
        f"TCP retransmission packets: {retransmissions:,}",
        "",
        table("Protocols", protocols.most_common(12), ("Protocol", "Packets")),
        "",
        table("Top destination IPs", [(ip, f"{n:,}") for ip, n in destinations.most_common(10)], ("IP", "Bytes sent to IP")),
        "",
        table("Top conversations", [(" ↔ ".join(pair), f"{n:,}") for pair, n in conversations.most_common(10)], ("IP pair", "Bytes")),
        "",
        table("DNS queries", domains.most_common(15), ("Domain", "Queries")),
        "",
        table("Traffic by minute", [(minute, f"{n:,}") for minute, n in sorted(minutes.items())], ("Minute", "Bytes")),
        "",
        "Counts describe captured packets only. Encrypted payloads cannot be read from this report. "
        "A retransmission alone does not prove a network fault."
    ]
    args.output.write_text("\n".join(sections) + "\n", encoding="utf-8")
    print(f"Analysed {total:,} packets. Report: {args.output.resolve()}")


if __name__ == "__main__":
    main()
