# NetRecon

NetRecon is a Python CLI for turning Nmap XML output into structured, analyst-friendly reconnaissance data.

## Status

**Core v0 complete; Intelligence layer in active development.** NetRecon reliably ingests Nmap XML, preserves scan context, and adds conservative evidence-based findings for analyst review.

## Core v0

- Parse Nmap XML generated with `-oX`
- Preserve scan metadata, run statistics, and Nmap scan scope (`<scaninfo>`) for evidence-aware comparisons
- Extract IPv4, IPv6, MAC addresses, and hostnames
- Extract TCP/UDP ports and states
- Preserve service name, product, version, extra info, tunnel, detection method, confidence, OS type, device type, and CPE data
- Preserve port-level and host-level Nmap NSE script results
- Produce an analyst-friendly text summary
- Produce structured JSON output for automation
- Summarize multi-host scans with host counts, open-port totals, unique services, and repeated-service counts
- Produce per-host summaries with open-port counts, observed services, and finding counts
- Produce an analysis summary with total findings, affected hosts, and severity counts without assigning an arbitrary risk score
- Add stable finding IDs and categories for downstream processing
- Separate OS/platform CPE evidence from application/service CPE evidence
- Surface Windows RPC, NetBIOS, SMB, Telnet, and FTP exposure context
- Detect explicit SMB signing evidence reported by Nmap without guessing vulnerabilities
- Detect explicit HTTP directory listing evidence reported by Nmap
- Detect explicit Apache Debian default-page evidence from `http-title` as informational deployment context; validated end-to-end against a live Apache lab service
- Interpret Nmap `http-methods` evidence: standard `GET`/`HEAD` context stays informational, while explicitly reported `PUT`, `DELETE`, `TRACE`, `CONNECT`, or `PATCH` methods are surfaced for configuration review
- Interpret `ssl-enum-ciphers` evidence for legacy TLS 1.0/1.1 support and explicitly reported anonymous key exchange, preserving port-level provenance
- Detect explicitly expired or not-yet-valid TLS certificates from `ssl-cert` evidence using time-aware analysis; both states validated end-to-end against controlled HTTPS lab certificates
- Compare a user-supplied target hostname with certificate DNS SAN evidence and report a TLS identity mismatch only when both sides are explicit; validated with controlled matching and mismatching HTTPS lab cases
- Summarize `ssh2-enum-algos` results as a port-scoped SSH algorithm inventory for analyst review; validated against a controlled OpenSSH lab service
- Handle missing, malformed, non-Nmap, and empty scan input
- Map services observed across multiple hosts, preserving endpoint product/version context
- Compare scans with evidence-aware Exposure Changes: `NEW`, `NO_LONGER_OPEN`, `CHANGED`, and `HOST_NOT_OBSERVED`
- Compare evidence-based findings over time with Analysis Changes: `NEW` and `NO_LONGER_OBSERVED`
- Protect change analysis from false conclusions when a host or port was not included in the later scan
- Run automated tests with GitHub Actions

## Quick start

Generate XML with Nmap on a system or network you are authorized to test:

```bash
nmap -sV -oX scan.xml <authorized-target>
```

Read the scan as a terminal report:

```bash
python netrecon.py scan.xml
```

Produce JSON:

```bash
python netrecon.py scan.xml --format json
```

Add evidence-based analysis:

```bash
python netrecon.py scan.xml --analyze
```

Return scan data and findings in one JSON document:

```bash
python netrecon.py scan.xml --analyze --format json
```

Compare exposure between two scans:

```bash
python netrecon.py before.xml after.xml --diff
```

Compare evidence-based findings between two scans:

```bash
python netrecon.py before.xml after.xml --analysis-diff
```

Try the included safe sample:

```bash
python netrecon.py examples/sample.xml
```

Run all tests:

```bash
python -m unittest discover -s tests -v
```

## Architecture

- `netrecon.py` — CLI entry point
- `parser.py` — Nmap XML ingestion and validation
- `models.py` — immutable scan, host, port, and script data models
- `analyzer.py` — conservative evidence-based findings
- `network_summary.py` — network-level host, port, and service summaries
- `host_summary.py` — descriptive per-host summaries
- `analysis_summary.py` — finding counts and severity distribution
- `scan_diff.py` — evidence-aware open-port exposure comparison
- `analysis_diff.py` — evidence-aware finding comparison across scans
- `reporter.py` — text and JSON rendering
- `tests/` — automated tests
- `examples/` — safe example input

## Intelligence principles

NetRecon keeps observations separate from findings. An open port is not automatically treated as a vulnerability, and service or OS detection is not treated as definitive proof. Findings are created from explicit scan evidence and include stable IDs, categories, evidence, and recommended follow-up.

Current Intelligence coverage is intentionally conservative. New rules are added incrementally, covered by automated tests, and validated against real authorized lab scans before being relied on in analyst workflows. Multi-host summarization and cross-host shared-service mapping have also been validated end-to-end against a two-host lab scan, including HTTP services implemented by different products on different ports.

Change intelligence follows the same evidence-first rule. NetRecon does not treat a missing host as closed ports, does not treat an unscanned port as closed, and does not treat an uncollected port-scoped finding as resolved. Exposure and analysis comparisons use observed host and Nmap port-scope context so that absence of observation is not silently converted into a state change. These safeguards have been validated with controlled scan-to-scan lab cases.

## Responsible use

Use NetRecon only with scan data from systems you own or are explicitly authorized to test.
