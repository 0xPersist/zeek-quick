# zeek-quick

CLI triage tool for Zeek logs. Feed it a log file and get an instant summary of top talkers, beacons, suspicious domains, malicious user agents, and bad certs without loading up a full SIEM.

Supports `conn.log`, `dns.log`, `http.log`, and `ssl.log` in both TSV and JSON formats.

---

## Features

- Auto-detects log type from filename or field headers
- **conn.log**: top talkers by bytes, long-duration connections, beacon detection
- **dns.log**: high-frequency queries, suspicious TLDs, rare domains
- **http.log**: suspicious user agents, suspicious URIs, top destinations
- **ssl.log**: self-signed certs, expired certs, rare JA3 hashes
- Dual beacon detection: frequency threshold **or** interval variance (coefficient of variation) — see caveats below
- Color-coded terminal output
- JSON export for pipeline integration
- Sample logs included for testing

---

## Install

```bash
git clone https://github.com/0xPersist/zeek-quick.git
cd zeek-quick
pip install -r requirements.txt
```

---

## Usage

```
usage: zeek-quick [-h] [--type TYPE] [--top N] [--long-duration SECS]
                  [--beacon-min COUNT] [--beacon-jitter FLOAT]
                  [--high-freq COUNT] [--rare-threshold COUNT]
                  [--json] [--out FILE] [--no-banner]
                  log

positional arguments:
  log                   Path to Zeek log file

options:
  --type TYPE           Force log type: conn, dns, http, ssl
  --top N               Number of top results to show (default: 10)
  --long-duration SECS  Flag connections longer than N seconds (default: 300)
  --beacon-min COUNT    Min connections to flag as beacon (default: 20)
  --beacon-jitter FLOAT Max interval CV for beacon detection (default: 0.3)
  --high-freq COUNT     DNS query count threshold for high-frequency (default: 100)
  --rare-threshold COUNT Query/UA count considered rare (default: 2)
  --json                Output results as JSON
  --out FILE            Write JSON output to file
  --no-banner           Suppress banner
```

---

## Examples

**Triage a conn.log:**
```bash
zeek-quick conn.log
```

**Lower beacon threshold for sensitivity:**
```bash
zeek-quick conn.log --beacon-min 10 --beacon-jitter 0.2
```

**DNS log with custom high-frequency threshold:**
```bash
zeek-quick dns.log --high-freq 50
```

**HTTP log, JSON output:**
```bash
zeek-quick http.log --json --out http_results.json
```

**SSL log, pipe-friendly:**
```bash
zeek-quick ssl.log --no-banner --json | jq '.self_signed'
```

**Test with included sample logs:**
```bash
zeek-quick samples/conn.log
zeek-quick samples/dns.log
zeek-quick samples/http.log
zeek-quick samples/ssl.log
```

---

## Beacon Detection

Two methods run simultaneously. A connection pair is flagged if either condition is met.

**Frequency threshold**: flags src/dst pairs that connect more than `--beacon-min` times. Default is 20 connections. This condition uses **no timing evidence at all** — any high-volume pair matches, including port scanners and ordinary chatty services.

**Interval variance**: calculates the coefficient of variation (CV) of connection intervals. Low CV means highly regular timing, which is a strong beacon indicator. Default threshold is 0.3 (30% variance). This catches beacons that add slight jitter to evade simple frequency checks.

Both methods report independently, so check the `reasons` field before treating a hit as a beacon. A result citing only `frequency=` has not been shown to be regular in time; one citing `interval_cv=` has.

**Tuning.** On a noisy or internet-facing capture the frequency condition dominates. Measured on a 105,918-record capture whose sensor sat on the destination: 920 pairs were flagged, **754 of them (82%) on frequency alone**, and 908 were inbound scanners. The real beacon in that capture was found and correctly measured (`interval_cv=0.163`, `mean_interval_s=272.48`) but ranked 7th. **Raise `--beacon-min` to cut scanner noise** — at 2000 the same capture yields 3 results. Note that raising it also hides genuinely slow beacons, which the frequency condition cannot see in any case; those are what `--beacon-jitter` is for.

---

## Log Format Support

Handles both Zeek TSV (default) and JSON log formats. TSV format requires a `#fields` header line. JSON format expects one JSON object per line (NDJSON).

Compressed logs can be streamed straight in. Pass `-` (or `/dev/stdin`) to read the pipe:

```bash
zcat conn.log.gz | zeek-quick - --type conn
gunzip -c conn.log.gz | zeek-quick /dev/stdin --type conn
```

Piped input is parsed in a single pass and produces byte-identical output to running against the same data as a file. Give `--type` when reading a pipe, since there is no filename to detect the log type from.

Note that a gzipped file **path** is not read directly — decompress it or stream it as above.

---

## Sample Logs

The `samples/` directory contains sanitized example logs for each supported type. External IPs use RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and internal hosts use RFC 1918 private space (`10.0.0.x`). No real infrastructure data is included.

---

## Tests

```bash
python3 run_tests.py
```

Covers input handling: file path, piped stdin via both `-` and `/dev/stdin`, byte-identical output between the two, the compressed-log idiom end to end, NDJSON over a pipe, and clean handling of empty, malformed and missing input.

---

## Requirements

- Python 3.8+
- `colorama` (optional, for colored output)
- No other dependencies beyond stdlib

---

## License

MIT. See [LICENSE](LICENSE).

---

*by [0xPersist](https://github.com/0xPersist)*
