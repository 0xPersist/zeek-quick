<div align="center">

<br/>

# AVERY

**Advanced Visibility & Endpoint Response**

*APT detection infrastructure. Built for threat hunters, not dashboards.*

<br/>

[![Platform](https://img.shields.io/badge/AlmaLinux-9.7-0d597f?style=flat-square&logo=redhat&logoColor=white)](https://almalinux.org)
[![SIEM](https://img.shields.io/badge/Wazuh-SIEM%20%2F%20EDR-005571?style=flat-square)](https://wazuh.com)
[![NDR](https://img.shields.io/badge/Zeek%20%2B%20RITA%20%2B%20Arkime-NDR-2b6cb0?style=flat-square)](https://zeek.org)
[![Intel](https://img.shields.io/badge/MISP%20%2B%20OpenCTI-Threat%20Intel-6b46c1?style=flat-square)](https://www.misp-project.org)
[![SOAR](https://img.shields.io/badge/Shuffle-SOAR-1a202c?style=flat-square)](https://shuffler.io)
[![Network](https://img.shields.io/badge/Tailscale-Zero%20Trust%20Mesh-3b82f6?style=flat-square)](https://tailscale.com)
[![Status](https://img.shields.io/badge/status-active%20development-22c55e?style=flat-square)]()

</div>

<br/>

---

## Background

APT actors don't trigger rules. They move slowly, blend into normal traffic, and wait. Most detection stacks are built around signature matching and volume thresholds, which means a patient adversary with clean tooling can sit inside a network for months before anyone notices, if they're noticed at all.

AVERY is a self-hosted SOC stack I built specifically to close that gap. The focus is behavioral detection: beaconing analysis, encrypted traffic profiling, lateral movement patterns, and network edge telemetry that most deployments don't collect at all. Everything runs on AlmaLinux over a Tailscale overlay so no component is exposed to the public internet.

The scripts in this repo are what actually built and configured the infrastructure.

---

## Architecture

```
                        +-----------------------------------------+
                        |           THREAT INTELLIGENCE           |
                        |         MISP  .  OpenCTI  .  GeoIP      |
                        +------------------+----------------------+
                                           | IOC enrichment
          +--------------------------------+----------------------------------------+
          |                                                                         |
          |                     WAZUH  (SIEM / EDR)                                |
          |          log correlation . rule engine . agent telemetry               |
          |                                                                         |
          +--------+----------------------------+----------------------------+------+
                   |                            |                            |
       +-----------+----------+   +-------------+---------+   +-------------+------+
       |   NETWORK DETECTION  |   |    FULL PACKET        |   |     ENDPOINT       |
       |                      |   |      CAPTURE          |   |                    |
       |  Zeek  .  Suricata   |   |      Arkime           |   |   Wazuh Agents     |
       |  RITA (beaconing)    |   |                       |   |   Velociraptor     |
       +-----------+----------+   +-------------+---------+   +--------------------+
                   |                            |
       +-----------+----------------------------+----------------------------------+
       |                         TELEMETRY SOURCES                                |
       |  Router edge agent  .  Suricata EVE JSON  .  Zeek conn/dns/ssl logs      |
       +------------------------------------------+-------------------------------+
                                                  |
                                     +------------+------------+
                                     |          SOAR           |
                                     |         Shuffle         |
                                     |   webhook orchestration |
                                     +------------+------------+
                                                  |
                                     +------------+------------+
                                     |        ALERTING         |
                                     |   Slack . Block Kit     |
                                     |   MITRE ATT&CK enriched |
                                     +-------------------------+

    All inter-service communication runs over Tailscale.
    Nothing listens on a public interface.
```

---

## Stack

| Layer | Component | Function |
|---|---|---|
| SIEM / EDR | [Wazuh](https://wazuh.com) | Log correlation, rule-based detection, agent telemetry |
| Full packet capture | [Arkime](https://arkime.com) | PCAP indexing and session reconstruction |
| Beaconing / C2 | [RITA](https://github.com/activecm/rita) | Statistical analysis of Zeek conn logs for beacon and C2 patterns |
| Network metadata | [Zeek](https://zeek.org) | Protocol parsing: conn, DNS, SSL/TLS, HTTP |
| IDS | [Suricata](https://suricata.io) | Signature detection, EVE JSON output piped to Wazuh |
| Threat intelligence | [MISP](https://www.misp-project.org) | IOC management and indicator correlation |
| Threat intelligence | [OpenCTI](https://www.opencti.io) | Structured CTI, STIX2, MITRE ATT&CK |
| SOAR | [Shuffle](https://shuffler.io) | Alert orchestration, automated playbooks |
| GeoIP | MaxMind GeoIP2 | ASN and geolocation enrichment |
| DFIR | [Velociraptor](https://www.rapid7.com/products/velociraptor/) | Live endpoint forensics and artifact collection |
| Overlay network | [Tailscale](https://tailscale.com) | Zero-trust mesh, all services bound to Tailscale interface |

---

## What It Detects

**Beaconing and C2**
RITA does statistical analysis on Zeek conn logs looking at connection frequency, timing jitter, and data transfer regularity. It will surface C2 behavior even if the infrastructure has no known signature, which is the whole point.

**Encrypted traffic fingerprinting**
JA3/JA3S hashes profile TLS client and server behavior without touching the payload. Unusual client hellos, mismatched cipher suites, anomalous server fingerprints all show up at line rate.

**DNS**
Query volume per host, entropy, NXDomain rates, tunneling heuristics. DNS is still one of the most reliable C2 channels and most deployments barely look at it.

**Lateral movement**
Custom Wazuh rules on Zeek conn logs catch east-west SSH, RDP, SMB, Telnet, and VNC. An adversary moving laterally generates conn log entries even when they're not triggering any endpoint alerts.

**Network edge telemetry**
A lightweight agent running on the router ships conntrack session state, top destination IPs and ports, and LAN/guest neighbor tables directly into Wazuh. This gives visibility below the host layer that you don't get from endpoint agents alone.

**MITRE ATT&CK context**
Every alert gets tactic and technique identifiers where mapped. The Slack integration surfaces that context on every notification so you're not cross-referencing manually during triage.

---

## Repo Structure

```
AVERY/
|
+-- wazuh/
|   +-- setup-syslog-listener.sh     # Tailscale-aware syslog ingestion setup
|   +-- install-rules.sh             # Idempotent Suricata + Zeek rule installer
|   +-- integrations/
|       +-- custom-slack.py          # MITRE-enriched Slack alerting
|
+-- agents/
|   +-- avery-telemetry.sh           # Router edge telemetry agent (OpenWRT)
|
+-- config/
|   +-- .env.example
|
+-- docs/
    +-- data-flow.md
    +-- VISION.md
```

---

## Scripts

### `wazuh/setup-syslog-listener.sh`

Detects the Tailscale interface and IP automatically, injects a `<remote>` stanza into `ossec.conf` scoped to Tailscale CGNAT space on UDP 5514, restarts Wazuh, and confirms the listener came up.

```bash
sudo bash wazuh/setup-syslog-listener.sh
```

### `wazuh/install-rules.sh`

Installs custom detection rules idempotently. Writes a rollback script before modifying anything and traps on failure. Deploys:

- Suricata DNS visibility rule (elevates the silent base rule 86603 from level 0 to observable)
- Zeek conn.log rules for east-west detection on SSH (22), RDP (3389), SMB (445), Telnet (23), VNC (5900)

Marker strings prevent duplicate injection on re-runs.

```bash
sudo bash wazuh/install-rules.sh
```

### `wazuh/integrations/custom-slack.py`

Replaces the Wazuh built-in Slack integration with structured Block Kit messages. Each alert includes severity emoji, rule description, rule ID, agent name, timestamp, and MITRE tactic/technique when available. Webhook URL and alert threshold come from environment variables.

### `agents/avery-telemetry.sh`

POSIX sh with no dependencies beyond `nc`. Designed for OpenWRT. Ships RFC 3164 UDP syslog to the Wazuh manager containing conntrack session count, top 5 destination ports, top 5 destination IPs, and LAN/guest neighbor tables.

```bash
# Copy to router
scp agents/avery-telemetry.sh root@<router-ip>:/root/

# Add to cron on the router
ssh root@<router-ip> 'echo "*/5 * * * * /root/avery-telemetry.sh" >> /etc/crontabs/root'
```

---

## Configuration

```bash
cp config/.env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `WAZUH_TAILSCALE_IP` | Tailscale IP of the Wazuh manager | required |
| `WAZUH_SYSLOG_PORT` | UDP port for syslog ingestion | `5514` |
| `SLACK_WEBHOOK_URL` | Incoming webhook URL | required |
| `ALERT_LEVEL_THRESHOLD` | Minimum Wazuh rule level to alert on | `7` |
| `MAXMIND_DB_PATH` | Path to GeoLite2-City.mmdb | `/opt/geoip/GeoLite2-City.mmdb` |

---

## Notes on Design

**AlmaLinux over Ubuntu**
RHEL-compatible, long support lifecycle, good ecosystem support for this specific tool stack. The choice matters less than consistency, but this has held up well.

**Tailscale for everything**
Binding services to specific firewall interfaces is brittle and easy to misconfigure. Tailscale gives each component a stable authenticated identity on a private overlay. The attack surface is much cleaner and there's no risk of accidentally exposing something to the public internet.

**`sed` instead of config rewrites**
`ossec.conf` accumulates state. Rewriting it on each run would destroy any tuning that had been done. Using `sed` with idempotency markers keeps things repeatable without being destructive.

**Custom Slack integration**
The built-in Wazuh Slack integration sends a wall of text. Block Kit messages with structured fields and MITRE context are actually usable during triage. The extra 80 lines of Python is worth it.

---

## Status

| Component | Status |
|---|---|
| Wazuh SIEM / EDR | operational |
| Zeek network metadata | operational |
| Suricata IDS | operational |
| RITA beaconing detection | operational |
| Arkime full packet capture | operational |
| MISP threat intelligence | operational |
| OpenCTI | operational |
| Velociraptor DFIR | operational |
| Router edge telemetry | operational |
| Wazuh to Slack alerting | operational |
| Shuffle SOAR orchestration | in progress |

---

## Contributing

Open an issue if you want to discuss the architecture or detection approach. See [docs/VISION.md](docs/VISION.md) for the longer-term research direction.

---

MIT License
