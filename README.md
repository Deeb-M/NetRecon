# NetRecon

NetRecon is a Python CLI for turning Nmap XML output into structured, analyst-friendly reconnaissance data.

## Status

**Core v0 complete.** The project can reliably ingest Nmap XML, preserve useful scan context, and produce both human-readable and machine-readable output. The next milestone is the analysis layer.

## Core v0

- Parse Nmap XML generated with `-oX`
- Preserve scan metadata and run statistics
- Extract IPv4, IPv6, MAC addresses, and hostnames
- Extract TCP/UDP ports and states
- Preserve service name, product, version, extra info, tunnel, detection method, and confidence
- Preserve port-level and host-level Nmap NSE script results
- Produce an analyst-friendly text summary
- Produce structured JSON output for automation
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
- `reporter.py` — text and JSON rendering
- `tests/` — automated tests
- `examples/` — safe example input

## Next milestone: Intelligence

The next development stage will analyze the normalized scan data and surface useful findings without pretending that an open port or a detected version is automatically a vulnerability. Findings will be evidence-based and kept separate from raw scan data.

## Responsible use

Use NetRecon only with scan data from systems you own or are explicitly authorized to test.
