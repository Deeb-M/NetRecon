# NetRecon

NetRecon is a Python CLI project for turning Nmap XML output into structured, analyst-friendly network reconnaissance data.

## Current status

Early Core development. The first milestone focuses on reliable Nmap XML ingestion before adding analysis or intelligence features.

## Core v0

- Parse Nmap XML generated with `-oX`
- Extract hosts and host status
- Extract hostnames and addresses
- Extract TCP/UDP ports and states
- Extract detected service, product, and version metadata
- Produce a readable terminal summary
- Reject missing, malformed, or non-Nmap XML input
- Automated parser tests

## Quick start

Generate XML with Nmap in an authorized lab or network:

```bash
nmap -sV -oX scan.xml <authorized-target>
```

Analyze the saved result:

```bash
python netrecon.py scan.xml
```

Try the included safe sample:

```bash
python netrecon.py examples/sample.xml
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Direction

NetRecon is intended to grow beyond reformatting Nmap output. Later milestones will focus on prioritization, context, analyst workflow, and reporting. Those features will be designed and validated before a public release.

## Responsible use

Use NetRecon only with scan data from systems you own or are explicitly authorized to test.
