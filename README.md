# NetRecon

NetRecon is a Python CLI for turning Nmap XML output into structured, analyst-friendly reconnaissance data.

## Status

**Core v0 complete; Intelligence layer in active development.** NetRecon reliably ingests Nmap XML, preserves scan context, and adds conservative evidence-based findings for analyst review.

## Core v0

- Parse Nmap XML generated with `-oX`
- Preserve scan metadata and run statistics
- Extract IPv4, IPv6, MAC addresses, and hostnames
- Extract TCP/UDP ports and states
- Preserve service name, product, version, extra info, tunnel, detection method, confidence, OS type, device type, and CPE data
- Preserve port-level and host-level Nmap NSE script results
- Produce an analyst-friendly text summary
- Produce structured JSON output for automation
- Add stable finding IDs and categories for downstream processing
- Separate OS/platform CPE evidence from application/service CPE evidence
- Surface Windows RPC, NetBIOS, SMB, Telnet, and FTP exposure context
- Detect explicit SMB signing evidence reported by Nmap without guessing vulnerabilities
- Detect explicit HTTP directory listing evidence reported by Nmap
- Interpret Nmap `http-methods` evidence: standard `GET`/`HEAD` context stays informational, while explicitly reported `PUT`, `DELETE`, `TRACE`, `CONNECT`, or `PATCH` methods are surfaced for configuration review
- Interpret `ssl-enum-ciphers` evidence for legacy TLS 1.0/1.1 support and explicitly reported anonymous key exchange, preserving port-level provenance
- Detect explicitly expired TLS certificates from `ssl-cert` evidence using time-aware analysis; validated end-to-end against a controlled expired-certificate HTTPS lab
- Handle missing, malformed, non-Nmap, and empty scan input
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
- `reporter.py` — text and JSON rendering
- `tests/` — automated tests
- `examples/` — safe example input

## Intelligence principles

NetRecon keeps observations separate from findings. An open port is not automatically treated as a vulnerability, and service or OS detection is not treated as definitive proof. Findings are created from explicit scan evidence and include stable IDs, categories, evidence, and recommended follow-up.

Current Intelligence coverage is intentionally conservative. New rules are added incrementally, covered by automated tests, and validated against real authorized lab scans before being relied on in analyst workflows.

## Responsible use

Use NetRecon only with scan data from systems you own or are explicitly authorized to test.
