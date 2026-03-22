#!/usr/bin/env python3
"""
zeek-quick — Zeek log triage tool
Author: 0xPersist
License: MIT
"""

import argparse
import json
import sys
import os
import csv
import math
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timezone

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

VERSION = "1.0.0"

BANNER = r"""
  _____           _                    _      _
 |__  /___ ___  | | __   __ _  _   _ (_) ___| | __
   / // _ / _ \ | |/ /  / _` || | | || |/ __| |/ /
  / /|  __/  __/|   <  | (_| || |_| || | (__|   <
 /____\___|\___||_|\_\  \__, | \__,_||_|\___|_|\_\
                          |_|
  zeek-quick v{version} — by 0xPersist
  Zeek log triage: conn, dns, http, ssl
""".format(version=VERSION)


# ── Color helpers ──────────────────────────────────────────────────────────────

def c(text, color):
    if not COLOR:
        return text
    colors = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "dim":    Style.DIM,
        "bold":   Style.BRIGHT,
        "magenta": Fore.MAGENTA,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def tag(label, color="cyan"):
    return c(f"[{label}]", color)


def section(title):
    print()
    print(c("─" * 60, "dim"))
    print(f"  {c(title, 'bold')}")
    print(c("─" * 60, "dim"))


# ── Zeek log parser ────────────────────────────────────────────────────────────

def parse_zeek_log(path: str) -> tuple:
    """
    Parse a Zeek TSV log file.
    Returns (fields, rows) where rows is a list of dicts.
    Handles both TSV (#fields) and JSON log formats.
    """
    fields = []
    rows   = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Peek at first line to determine format
            first = f.readline().strip()
            f.seek(0)

            # JSON format
            if first.startswith("{"):
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                if rows:
                    fields = list(rows[0].keys())
                return fields, rows

            # TSV format
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif fields:
                    values = line.split("\t")
                    if len(values) == len(fields):
                        rows.append(dict(zip(fields, values)))

    except FileNotFoundError:
        print(c(f"[!] File not found: {path}", "red"))
        sys.exit(1)
    except PermissionError:
        print(c(f"[!] Permission denied: {path}", "red"))
        sys.exit(1)

    return fields, rows


def detect_log_type(path: str, fields: list) -> str:
    """Detect Zeek log type from filename or fields."""
    name = os.path.basename(path).lower()

    if "conn" in name:    return "conn"
    if "dns" in name:     return "dns"
    if "http" in name:    return "http"
    if "ssl" in name:     return "ssl"

    # Field-based detection
    field_set = set(fields)
    if {"id.orig_h", "duration", "orig_bytes"}.issubset(field_set):  return "conn"
    if {"query", "qtype_name", "answers"}.issubset(field_set):        return "dns"
    if {"method", "host", "uri", "user_agent"}.issubset(field_set):   return "http"
    if {"server_name", "cipher", "ja3"}.issubset(field_set):          return "ssl"

    return "unknown"


def safe_float(val, default=0.0):
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def safe_int(val, default=0):
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def fmt_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ── conn.log analysis ──────────────────────────────────────────────────────────

def analyze_conn(rows: list, args) -> dict:
    results = {
        "top_talkers":        [],
        "long_connections":   [],
        "beacons":            [],
        "summary": {
            "total_connections": len(rows),
            "unique_src":        0,
            "unique_dst":        0,
            "total_bytes":       0,
        }
    }

    # Accumulators
    src_bytes   = defaultdict(int)
    dst_bytes   = defaultdict(int)
    pair_times  = defaultdict(list)   # (src, dst) -> [timestamps]
    pair_bytes  = defaultdict(int)
    src_ips     = set()
    dst_ips     = set()
    total_bytes = 0

    for row in rows:
        src = row.get("id.orig_h", row.get("orig_h", "-"))
        dst = row.get("id.resp_h", row.get("resp_h", "-"))
        ts  = safe_float(row.get("ts", 0))
        ob  = safe_int(row.get("orig_bytes", 0))
        rb  = safe_int(row.get("resp_bytes", 0))
        dur = safe_float(row.get("duration", 0))

        if src == "-" or dst == "-":
            continue

        src_ips.add(src)
        dst_ips.add(dst)
        total_bytes += ob + rb
        src_bytes[src] += ob + rb
        dst_bytes[dst] += ob + rb
        pair_times[(src, dst)].append(ts)
        pair_bytes[(src, dst)] += ob + rb

        # Long connections
        if dur >= args.long_duration:
            results["long_connections"].append({
                "src": src, "dst": dst,
                "duration": dur,
                "orig_bytes": ob,
                "resp_bytes": rb,
                "proto": row.get("proto", "-"),
                "service": row.get("service", "-"),
            })

    results["summary"]["unique_src"]  = len(src_ips)
    results["summary"]["unique_dst"]  = len(dst_ips)
    results["summary"]["total_bytes"] = total_bytes

    # Top talkers
    top = sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:args.top_n]
    results["top_talkers"] = [{"ip": ip, "bytes": b} for ip, b in top]

    # Beacon detection
    for (src, dst), times in pair_times.items():
        if len(times) < args.beacon_min_count:
            continue

        times_sorted = sorted(times)
        intervals    = [times_sorted[i+1] - times_sorted[i] for i in range(len(times_sorted)-1)]

        if not intervals:
            continue

        beacon = False
        reason = []

        # Method 1: frequency threshold
        if len(times) >= args.beacon_min_count:
            beacon = True
            reason.append(f"frequency={len(times)} connections")

        # Method 2: interval variance (low variance = regular beaconing)
        if len(intervals) >= 3:
            try:
                mean_interval = statistics.mean(intervals)
                stdev         = statistics.stdev(intervals)
                if mean_interval > 0:
                    cv = stdev / mean_interval  # coefficient of variation
                    if cv < args.beacon_jitter:
                        beacon = True
                        reason.append(f"interval_cv={cv:.3f} (regular timing)")
            except statistics.StatisticsError:
                pass

        if beacon:
            results["beacons"].append({
                "src":        src,
                "dst":        dst,
                "count":      len(times),
                "bytes":      pair_bytes[(src, dst)],
                "reasons":    reason,
                "mean_interval_s": round(statistics.mean(intervals), 2) if intervals else 0,
            })

    # Sort
    results["long_connections"].sort(key=lambda x: x["duration"], reverse=True)
    results["long_connections"] = results["long_connections"][:args.top_n]
    results["beacons"].sort(key=lambda x: x["count"], reverse=True)

    return results


def render_conn(results: dict):
    s = results["summary"]
    section("conn.log — Summary")
    print(f"  Total connections : {c(str(s['total_connections']), 'cyan')}")
    print(f"  Unique sources    : {s['unique_src']}")
    print(f"  Unique dest       : {s['unique_dst']}")
    print(f"  Total bytes       : {c(fmt_bytes(s['total_bytes']), 'cyan')}")

    section("Top Talkers")
    if results["top_talkers"]:
        for i, t in enumerate(results["top_talkers"], 1):
            print(f"  {c(str(i).rjust(2), 'dim')}. {c(t['ip'],'cyan'):<20} {c(fmt_bytes(t['bytes']), 'yellow')}")
    else:
        print(f"  {c('No data', 'dim')}")

    section("Long Duration Connections")
    if results["long_connections"]:
        for conn in results["long_connections"]:
            dur = conn["duration"]
            col = "red" if dur > 3600 else "yellow"
            print(f"  {c(conn['src'], 'cyan')} → {c(conn['dst'], 'white')}")
            print(f"    Duration : {c(f'{dur:.1f}s', col)}  Proto: {conn['proto']}  Service: {conn['service']}")
            print(f"    Bytes    : ↑{fmt_bytes(conn['orig_bytes'])} ↓{fmt_bytes(conn['resp_bytes'])}")
            print()
    else:
        print(f"  {c('No long connections found', 'dim')}")

    section("Beacon Detection")
    if results["beacons"]:
        for b in results["beacons"]:
            print(f"  {c('⚠', 'red')} {c(b['src'], 'cyan')} → {c(b['dst'], 'white')}")
            print(f"    Connections    : {c(str(b['count']), 'red')}")
            print(f"    Mean interval  : {b['mean_interval_s']}s")
            print(f"    Total bytes    : {fmt_bytes(b['bytes'])}")
            for r in b["reasons"]:
                print(f"    {c('→', 'yellow')} {r}")
            print()
    else:
        print(f"  {c('No beacons detected', 'green')}")


# ── dns.log analysis ───────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".pw",
    ".cc", ".su", ".to", ".ws", ".biz", ".info"
}

def analyze_dns(rows: list, args) -> dict:
    results = {
        "rare_domains":      [],
        "high_freq_queries": [],
        "suspicious_tlds":   [],
        "summary": {
            "total_queries":  len(rows),
            "unique_domains": 0,
            "unique_clients": 0,
        }
    }

    domain_counts  = Counter()
    client_domains = defaultdict(set)
    clients        = set()

    for row in rows:
        query  = row.get("query", "-")
        client = row.get("id.orig_h", row.get("orig_h", "-"))

        if query in ("-", "") or client == "-":
            continue

        domain_counts[query] += 1
        client_domains[client].add(query)
        clients.add(client)

        # Suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if query.endswith(tld):
                results["suspicious_tlds"].append({
                    "query":  query,
                    "client": client,
                    "tld":    tld,
                    "qtype":  row.get("qtype_name", "-"),
                })
                break

    results["summary"]["unique_domains"] = len(domain_counts)
    results["summary"]["unique_clients"] = len(clients)

    # Rare domains (queried only once)
    rare = [(d, c) for d, c in domain_counts.items() if c <= args.rare_threshold]
    rare.sort(key=lambda x: x[1])
    results["rare_domains"] = [{"domain": d, "count": c} for d, c in rare[:args.top_n]]

    # High frequency queries
    high = [(d, c) for d, c in domain_counts.items() if c >= args.high_freq]
    high.sort(key=lambda x: x[1], reverse=True)
    results["high_freq_queries"] = [{"domain": d, "count": c} for d, c in high[:args.top_n]]

    # Deduplicate suspicious TLDs
    seen = set()
    deduped = []
    for item in results["suspicious_tlds"]:
        key = (item["query"], item["client"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    results["suspicious_tlds"] = deduped[:args.top_n]

    return results


def render_dns(results: dict):
    s = results["summary"]
    section("dns.log — Summary")
    print(f"  Total queries   : {c(str(s['total_queries']), 'cyan')}")
    print(f"  Unique domains  : {s['unique_domains']}")
    print(f"  Unique clients  : {s['unique_clients']}")

    section("High Frequency Queries")
    if results["high_freq_queries"]:
        for item in results["high_freq_queries"]:
            col = "red" if item["count"] > 100 else "yellow"
            print(f"  {c(str(item['count']).rjust(6), col)}x  {c(item['domain'], 'cyan')}")
    else:
        print(f"  {c('None found', 'dim')}")

    section("Suspicious TLDs")
    if results["suspicious_tlds"]:
        for item in results["suspicious_tlds"]:
            print(f"  {c('⚠', 'red')} {c(item['query'], 'cyan')}")
            print(f"    Client : {item['client']}  TLD: {c(item['tld'], 'red')}  Type: {item['qtype']}")
    else:
        print(f"  {c('No suspicious TLDs found', 'green')}")

    section("Rare Domains (low query count)")
    if results["rare_domains"]:
        for item in results["rare_domains"][:20]:
            print(f"  {c(str(item['count']).rjust(4), 'dim')}x  {item['domain']}")
    else:
        print(f"  {c('None found', 'dim')}")


# ── http.log analysis ──────────────────────────────────────────────────────────

SUSPICIOUS_UA_PATTERNS = [
    "python-requests", "curl/", "wget/", "go-http-client",
    "masscan", "nmap", "nikto", "sqlmap", "dirbuster",
    "zgrab", "httpx", "nuclei",
]

def analyze_http(rows: list, args) -> dict:
    results = {
        "rare_user_agents":   [],
        "suspicious_agents":  [],
        "top_destinations":   [],
        "suspicious_uris":    [],
        "summary": {
            "total_requests": len(rows),
            "unique_hosts":   0,
            "unique_clients": 0,
        }
    }

    ua_counts   = Counter()
    host_counts = Counter()
    clients     = set()

    for row in rows:
        ua     = row.get("user_agent", "-")
        host   = row.get("host", "-")
        uri    = row.get("uri", "-")
        client = row.get("id.orig_h", row.get("orig_h", "-"))
        method = row.get("method", "-")

        if client != "-":
            clients.add(client)
        if ua not in ("-", ""):
            ua_counts[ua] += 1
        if host not in ("-", ""):
            host_counts[host] += 1

        # Suspicious URIs
        sus_uri_patterns = [
            "../", "..", "/etc/passwd", "/etc/shadow",
            "cmd=", "exec=", "eval(", "base64",
            "/wp-admin", "/phpmyadmin", "/.git/",
            "union+select", "union select", "<script",
        ]
        for pattern in sus_uri_patterns:
            if pattern.lower() in uri.lower():
                results["suspicious_uris"].append({
                    "client": client,
                    "method": method,
                    "host":   host,
                    "uri":    uri[:120],
                    "pattern": pattern,
                })
                break

        # Suspicious user agents
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern.lower() in ua.lower():
                results["suspicious_agents"].append({
                    "client": client,
                    "ua":     ua,
                    "host":   host,
                    "pattern": pattern,
                })
                break

    results["summary"]["unique_hosts"]   = len(host_counts)
    results["summary"]["unique_clients"] = len(clients)

    # Top destinations
    top = host_counts.most_common(args.top_n)
    results["top_destinations"] = [{"host": h, "count": c} for h, c in top]

    # Rare user agents
    rare = [(ua, c) for ua, c in ua_counts.items() if c <= args.rare_threshold]
    rare.sort(key=lambda x: x[1])
    results["rare_user_agents"] = [{"ua": ua, "count": c} for ua, c in rare[:args.top_n]]

    # Deduplicate
    seen = set()
    deduped_agents = []
    for item in results["suspicious_agents"]:
        key = (item["client"], item["ua"])
        if key not in seen:
            seen.add(key)
            deduped_agents.append(item)
    results["suspicious_agents"] = deduped_agents[:args.top_n]

    seen = set()
    deduped_uris = []
    for item in results["suspicious_uris"]:
        key = (item["client"], item["uri"])
        if key not in seen:
            seen.add(key)
            deduped_uris.append(item)
    results["suspicious_uris"] = deduped_uris[:args.top_n]

    return results


def render_http(results: dict):
    s = results["summary"]
    section("http.log — Summary")
    print(f"  Total requests  : {c(str(s['total_requests']), 'cyan')}")
    print(f"  Unique hosts    : {s['unique_hosts']}")
    print(f"  Unique clients  : {s['unique_clients']}")

    section("Top Destinations")
    if results["top_destinations"]:
        for i, item in enumerate(results["top_destinations"], 1):
            print(f"  {c(str(i).rjust(2), 'dim')}. {c(item['host'], 'cyan'):<40} {c(str(item['count']), 'yellow')} requests")
    else:
        print(f"  {c('No data', 'dim')}")

    section("Suspicious User Agents")
    if results["suspicious_agents"]:
        for item in results["suspicious_agents"]:
            print(f"  {c('⚠', 'red')} {c(item['ua'], 'yellow')}")
            print(f"    Client  : {item['client']}  Host: {item['host']}")
            print(f"    Matched : {c(item['pattern'], 'red')}")
            print()
    else:
        print(f"  {c('No suspicious agents found', 'green')}")

    section("Suspicious URIs")
    if results["suspicious_uris"]:
        for item in results["suspicious_uris"]:
            print(f"  {c('⚠', 'red')} {c(item['method'], 'cyan')} {item['host']}{item['uri']}")
            print(f"    Client  : {item['client']}  Pattern: {c(item['pattern'], 'red')}")
            print()
    else:
        print(f"  {c('No suspicious URIs found', 'green')}")

    section("Rare User Agents")
    if results["rare_user_agents"]:
        for item in results["rare_user_agents"][:15]:
            print(f"  {c(str(item['count']).rjust(4), 'dim')}x  {item['ua'][:80]}")
    else:
        print(f"  {c('None found', 'dim')}")


# ── ssl.log analysis ───────────────────────────────────────────────────────────

def analyze_ssl(rows: list, args) -> dict:
    results = {
        "self_signed":      [],
        "expired_certs":    [],
        "rare_ja3":         [],
        "summary": {
            "total_connections": len(rows),
            "unique_servers":    0,
            "unique_clients":    0,
        }
    }

    servers = set()
    clients = set()
    ja3_counts = Counter()

    now_ts = datetime.now(timezone.utc).timestamp()

    for row in rows:
        client  = row.get("id.orig_h", row.get("orig_h", "-"))
        server  = row.get("id.resp_h", row.get("resp_h", "-"))
        sni     = row.get("server_name", "-")
        valid   = row.get("validation_status", "-")
        ja3     = row.get("ja3", "-")
        ja3s    = row.get("ja3s", "-")
        cert_ts = row.get("cert_chain_fuids", "-")
        not_after = row.get("notAfter", row.get("not_after", "-"))

        if client != "-": clients.add(client)
        if server != "-": servers.add(server)
        if ja3 not in ("-", ""):
            ja3_counts[ja3] += 1

        # Self-signed
        if "self signed" in str(valid).lower() or "self-signed" in str(valid).lower():
            results["self_signed"].append({
                "client": client,
                "server": server,
                "sni":    sni,
                "validation": valid,
            })

        # Expired certs
        if "expired" in str(valid).lower():
            results["expired_certs"].append({
                "client": client,
                "server": server,
                "sni":    sni,
                "not_after": not_after,
            })

    results["summary"]["unique_servers"] = len(servers)
    results["summary"]["unique_clients"] = len(clients)

    # Rare JA3 hashes
    rare = [(j, c) for j, c in ja3_counts.items() if c <= args.rare_threshold and j != "-"]
    rare.sort(key=lambda x: x[1])
    results["rare_ja3"] = [{"ja3": j, "count": c} for j, c in rare[:args.top_n]]

    # Deduplicate
    for key in ("self_signed", "expired_certs"):
        seen = set()
        deduped = []
        for item in results[key]:
            k = (item["client"], item["server"])
            if k not in seen:
                seen.add(k)
                deduped.append(item)
        results[key] = deduped[:args.top_n]

    return results


def render_ssl(results: dict):
    s = results["summary"]
    section("ssl.log — Summary")
    print(f"  Total connections : {c(str(s['total_connections']), 'cyan')}")
    print(f"  Unique servers    : {s['unique_servers']}")
    print(f"  Unique clients    : {s['unique_clients']}")

    section("Self-Signed Certificates")
    if results["self_signed"]:
        for item in results["self_signed"]:
            print(f"  {c('⚠', 'red')} {c(item['client'], 'cyan')} → {c(item['server'], 'white')}")
            print(f"    SNI        : {item['sni']}")
            print(f"    Validation : {c(item['validation'], 'red')}")
            print()
    else:
        print(f"  {c('No self-signed certs found', 'green')}")

    section("Expired Certificates")
    if results["expired_certs"]:
        for item in results["expired_certs"]:
            print(f"  {c('⚠', 'yellow')} {c(item['client'], 'cyan')} → {c(item['server'], 'white')}")
            print(f"    SNI       : {item['sni']}")
            print(f"    Not After : {c(item['not_after'], 'yellow')}")
            print()
    else:
        print(f"  {c('No expired certs found', 'green')}")

    section("Rare JA3 Hashes")
    if results["rare_ja3"]:
        for item in results["rare_ja3"]:
            print(f"  {c(str(item['count']).rjust(4), 'dim')}x  {c(item['ja3'], 'magenta')}")
    else:
        print(f"  {c('None found', 'dim')}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="zeek-quick",
        description="Zeek log triage tool — rapid analysis of conn, dns, http, and ssl logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  zeek-quick conn.log
  zeek-quick dns.log --top 20 --high-freq 50
  zeek-quick http.log --json
  zeek-quick ssl.log --out results.json
  zeek-quick conn.log --beacon-min 10 --beacon-jitter 0.2

log types supported:
  conn.log  — top talkers, long connections, beacon detection
  dns.log   — high freq queries, suspicious TLDs, rare domains
  http.log  — suspicious UAs, suspicious URIs, top destinations
  ssl.log   — self-signed certs, expired certs, rare JA3 hashes
        """,
    )

    parser.add_argument("log",              help="Path to Zeek log file")
    parser.add_argument("--type",           help="Force log type (conn/dns/http/ssl)")
    parser.add_argument("--top",            type=int,   default=10,   dest="top_n",
                        help="Number of top results to show (default: 10)")
    parser.add_argument("--long-duration",  type=float, default=300.0,
                        help="Flag connections longer than N seconds (default: 300)")
    parser.add_argument("--beacon-min",     type=int,   default=20,   dest="beacon_min_count",
                        help="Minimum connections to flag as beacon (default: 20)")
    parser.add_argument("--beacon-jitter",  type=float, default=0.3,  dest="beacon_jitter",
                        help="Max interval coefficient of variation for beacon (default: 0.3)")
    parser.add_argument("--high-freq",      type=int,   default=100,  dest="high_freq",
                        help="DNS queries above this count flagged as high-frequency (default: 100)")
    parser.add_argument("--rare-threshold", type=int,   default=2,    dest="rare_threshold",
                        help="Query/UA count at or below this is considered rare (default: 2)")
    parser.add_argument("--json",           action="store_true", help="Output results as JSON")
    parser.add_argument("--out",            help="Write JSON output to file")
    parser.add_argument("--no-banner",      action="store_true", help="Suppress banner")
    parser.add_argument("--version",        action="version", version=f"zeek-quick {VERSION}")

    args = parser.parse_args()

    if not args.no_banner:
        print(c(BANNER, "cyan"))

    if not args.json:
        print(c(f"[*] Loading {args.log} ...", "dim"))
    fields, rows = parse_zeek_log(args.log)

    if not rows:
        print(c("[!] No records parsed. Check the file format.", "red"))
        sys.exit(1)

    log_type = args.type if args.type else detect_log_type(args.log, fields)

    if log_type == "unknown":
        print(c("[!] Could not detect log type. Use --type conn|dns|http|ssl", "red"))
        sys.exit(1)

    if not args.json:
        print(c(f"[*] Detected log type: {log_type}  |  Records: {len(rows)}", "dim"))

    # Analyze
    if log_type == "conn":
        results = analyze_conn(rows, args)
        if not args.json:
            render_conn(results)

    elif log_type == "dns":
        results = analyze_dns(rows, args)
        if not args.json:
            render_dns(results)

    elif log_type == "http":
        results = analyze_http(rows, args)
        if not args.json:
            render_http(results)

    elif log_type == "ssl":
        results = analyze_ssl(rows, args)
        if not args.json:
            render_ssl(results)

    else:
        print(c(f"[!] Unsupported log type: {log_type}", "red"))
        sys.exit(1)

    # JSON output
    if args.json or args.out:
        output = json.dumps(results, indent=2)
        if args.json:
            print(output)
        if args.out:
            with open(args.out, "w") as f:
                f.write(output)
            print(c(f"\n[+] Results written to {args.out}", "green"))

    print()


if __name__ == "__main__":
    main()
