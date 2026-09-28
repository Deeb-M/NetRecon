# NetRecon

NetRecon is a Python CLI for turning Nmap XML output into structured, analyst-friendly reconnaissance data.

## Status

**v0.1.0 — Alpha. Core functionality is stable and covered by automated tests; the Intelligence layer remains under active development.** NetRecon reliably ingests Nmap XML, preserves scan context, and adds conservative evidence-based findings for analyst review.

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
- Compare scans with evidence-aware Exposure Changes: `NEW`, `NO_LONGER_OPEN`, `CHANGED`, `HOST_NOT_OBSERVED`, `HOST_NEWLY_OBSERVED`, `HOST_UP`, and `HOST_DOWN`
- Compare evidence-based findings over time with Analysis Changes: `NEW`, `NEWLY_OBSERVED`, and `NO_LONGER_OBSERVED`
- Preserve NSE evidence provenance so change analysis can distinguish a real finding change from a script that was simply not collected
- Protect change analysis from false conclusions when a host or port was not included in the later scan
- Show `Before Coverage` and `After Coverage` from Nmap `<scaninfo>` in both Exposure Diff and Analysis Diff reports
- Flag whether scan coverage changed and explain the difference with `Newly Scanned` and `No Longer Scanned` protocol/port entries; large coverage sets are summarized in text while full detail remains available in JSON
- Keep coverage changes separate from exposure or finding changes: a port that was not scanned is not treated as closed or resolved
- Summarize scan-to-scan changes by type before listing individual changes
- Produce machine-readable JSON for Exposure Changes and Analysis Changes, including change summaries
- Combine both comparison views in one analyst workflow with `--combined-diff` while keeping exposure and finding changes explicitly separate
- Summarize open-endpoint history across multiple timestamped scans with first/last observation times, open-observation counts, and evidence-aware observation opportunities via `--history`
- Summarize evidence-backed finding history across multiple timestamped scans with first/last observation times and evidence-aware opportunities via `--finding-history`
- Run automated tests with GitHub Actions

## Installation

NetRecon requires Python 3.10 or newer and has no runtime third-party dependencies.

On Kali Linux and other distributions that protect the system Python environment, install the current public release in a virtual environment:

```bash
git clone https://github.com/Deeb-M/NetRecon.git
cd NetRecon
git checkout v0.1.0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

This checks out the exact `v0.1.0` release instead of the development `main` branch.

To test the latest development version instead, clone the repository and remain on `main`.

The installed CLI can then be invoked as `netrecon`.

## Quick start

Generate XML with Nmap on a system or network you are authorized to test:

```bash
nmap -sV -oX scan.xml <authorized-target>
```

Read the scan as a terminal report:

```bash
netrecon scan.xml
```

Produce JSON:

```bash
netrecon scan.xml --format json
```

Add evidence-based analysis:

```bash
netrecon scan.xml --analyze
```

Return scan data and findings in one JSON document:

```bash
netrecon scan.xml --analyze --format json
```

Compare exposure between two scans:

```bash
netrecon before.xml after.xml --diff
```

Return exposure changes as JSON:

```bash
netrecon before.xml after.xml --diff --format json
```

Compare evidence-based findings between two scans:

```bash
netrecon before.xml after.xml --analysis-diff
```

Return analysis changes as JSON, including finding evidence provenance:

```bash
netrecon before.xml after.xml --analysis-diff --format json
```

Review exposure and evidence-based finding changes together without merging their semantics:

```bash
netrecon before.xml after.xml --combined-diff
```

Return the combined workflow as JSON with separate `exposure` and `analysis` objects:

```bash
netrecon before.xml after.xml --combined-diff --format json
```

Summarize repeated open-endpoint observations across two or more timestamped Nmap XML scans:

```bash
netrecon --history scan1.xml scan2.xml scan3.xml
```

Return the same history as machine-readable JSON:

```bash
netrecon --history scan1.xml scan2.xml scan3.xml --format json
```

History is deliberately observational. `observations` counts scans where an endpoint was actually observed open; `opportunities` counts scans where that host was observed up and the port/protocol was in Nmap's scan scope. NetRecon does not turn this into an uptime percentage or assume continuous exposure between scans.

Summarize repeated evidence-backed findings across two or more timestamped Nmap XML scans:

```bash
netrecon --finding-history scan1.xml scan2.xml scan3.xml
```

Return Finding History as machine-readable JSON:

```bash
netrecon --finding-history scan1.xml scan2.xml scan3.xml --format json
```

Finding History is evidence-aware: `observations` counts scans where the finding was emitted, while `opportunities` counts only scans where the same host was observed up and the finding's required evidence source was actually available. Missing NSE evidence is not treated as a negative result, and no persistence, duration, or risk score is inferred.

Try the included safe sample:

```bash
netrecon examples/sample.xml
```

The following safe comparison examples are available on the development `main` branch and are not included in the `v0.1.0` release.

To see an exposure change on `main`:

```bash
netrecon examples/before.xml examples/after.xml --diff
```

To see how improved service evidence changes the analysis on `main`:

```bash
netrecon examples/before.xml examples/after.xml --analysis-diff
```

To review both exposure and analysis changes in one workflow on `main`:

```bash
netrecon examples/before.xml examples/after.xml --combined-diff
```

Run all tests:

```bash
python -m unittest discover -s tests -v
```


## Investigation workflow (development main)

The development `main` branch can run a bounded investigation directly against an authorized target. Nmap remains the discovery and evidence-collection engine; NetRecon plans supported evidence, verifies what was actually observed, re-plans only when justified, and produces one terminal decision.

Plan the first supported evidence actions without collecting them:

```bash
netrecon --investigate <authorized-target>
```

Run the bounded collection workflow:

```bash
netrecon --investigate-collect <authorized-target>
```

Include the adaptive decision trail when reviewing why NetRecon continued, tried one supported alternative, or stopped:

```bash
netrecon --investigate-collect <authorized-target> --adaptive-plan
```

Use `--format json` for machine-readable output. A completed command can end with either a complete or stalled investigation; a stalled result is a valid bounded outcome, not a claim that the target is safe or that evidence was resolved. Explicit-approval requirements remain blocked until approved, attempted-but-unsatisfied requirements are not silently retried, and the final report preserves the terminal decision, explanation, synthesis, evidence provenance, and remaining requirement lifecycle.

Persist completed investigation syntheses in an append-only local history and compare the current terminal synthesis with prior runs:

```bash
netrecon --investigate-collect <authorized-target> --investigation-history investigation-history.jsonl
```

Investigation History stores synthesis records rather than raw scan authority. The resulting Investigation Memory is evidence-aware comparison context; it does not turn absence into resolution, assign a risk score, or authorize additional collection.

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
- `exposure_history.py` — descriptive open-endpoint history across timestamped scans
- `finding_history.py` — evidence-aware finding history across timestamped scans
- `evidence_gaps.py` — planner-derived missing-evidence guidance for analyst follow-up
- `investigation_orchestration.py` — bounded investigation controller, continuation assessment, authorization-aware collection, verification, and canonical final decisions
- `adaptive_investigation.py` — bounded continue/alternative/stop projection from controller state
- `investigation_explanation.py` — analyst-facing Known / Unresolved / Blocked / Next explanation
- `investigation_synthesis.py` — terminal investigation synthesis from final decision and analyst attention
- `investigation_memory.py` — evidence-aware comparison of investigation syntheses across runs
- `reporter.py` — text and JSON rendering
- `tests/` — automated tests
- `examples/` — safe example input

## Intelligence principles

NetRecon keeps observations separate from findings. An open port is not automatically treated as a vulnerability, and service or OS detection is not treated as definitive proof. Findings are created from explicit scan evidence and include stable IDs, categories, evidence, and recommended follow-up.

Current Intelligence coverage is intentionally conservative. New rules are added incrementally, covered by automated tests, and validated against real authorized lab scans before being relied on in analyst workflows. Multi-host summarization and cross-host shared-service mapping have also been validated end-to-end against a two-host lab scan, including HTTP services implemented by different products on different ports.

Host-level exposure changes distinguish observation from port state. A host that disappears from a later scan is reported once as `HOST_NOT_OBSERVED`; a host that appears for the first time is reported once as `HOST_NEWLY_OBSERVED`, even when it exposes multiple ports. When a host is present in both scans but changes Nmap status, NetRecon reports `HOST_UP` or `HOST_DOWN`. These host-level observations do not imply that individual ports opened, closed, or that findings were resolved; port and finding changes require their own supporting evidence. This avoids turning host visibility or reachability changes into misleading batches of per-port changes.

Change intelligence follows the same evidence-first rule. NetRecon does not treat a missing host as closed ports, does not treat an unscanned port as closed, and does not treat an uncollected evidence source as proof that a finding appeared or disappeared. Exposure and analysis comparisons use observed host, Nmap port-scope context, and NSE evidence provenance so that absence of observation is not silently converted into a state change.

Scan Coverage Intelligence makes that scope visible to the analyst instead of keeping it only inside comparison logic. Diff reports show the Nmap-reported coverage before and after, flag whether it changed, and identify numeric protocol/port pairs that were newly scanned or no longer scanned. Small differences remain explicit in text; large scopes and differences are summarized by port count to keep terminal output readable, while JSON retains the complete original scope and expanded difference lists. Coverage differences are descriptive measurement context only; they are not reported as exposure changes or finding changes. This behavior has been validated end-to-end with controlled lab comparisons, including a reduced-scope scan and a 1-port-to-1000-port comparison.

For NSE-derived findings, `NEW` means the same NSE evidence source was collected before and the finding was absent; `NEWLY_OBSERVED` means the evidence source was not collected before, so NetRecon only claims that the finding is newly observed; and `NO_LONGER_OBSERVED` requires the relevant evidence source to be collected again without supporting the previous finding. These semantics have been validated end-to-end with controlled `http-title` lab scans. Text reports include deterministic change-count summaries, and JSON output includes the same summary data for automation. Both analysis-change and exposure-change summaries have been validated end-to-end against real lab scan files.


## Evidence Gaps

On development `main`, `--evidence-gaps` turns the existing Evidence Planner into an analyst-facing next-action view without running Nmap:

```bash
netrecon scan.xml --evidence-gaps
netrecon scan.xml --evidence-gaps --format json
```

A gap means that the existing planner supports a specific evidence source for an already discovered service and that evidence is not present in the supplied scan. The fixed `purpose` explains why that evidence is useful for review; it is not a vulnerability, risk score, or claim that a weakness exists. Existing matching NSE evidence suppresses the gap whether Nmap stored it at port level or host level. Unsupported services do not create speculative gaps, and `Gaps: 0` means only that no planner-supported evidence is missing from that scan.

Real field validation on `main` used `stage-a-discovery.xml` and `windows-smb-detail.xml`. The discovery scan produced four expected gaps: SMB protocol/signing evidence on `445/tcp` and HTTP title/method evidence on `5357/tcp`. The detailed SMB scan produced `Gaps: 0`, confirming that real host-level SMB NSE evidence does not create false gaps. JSON validation preserved the same four discovery gaps and their host, port, protocol, script ID, and purpose.


## Responsible use

Use NetRecon only with scan data from systems you own or are explicitly authorized to test.

## License

NetRecon is released under the MIT License.

Created and maintained by Deeb Mzareb.


## Evidence Action Plan

On development `main`, `--evidence-actions` turns planner-supported missing evidence into grouped, transparent collection actions without running Nmap:

```bash
netrecon scan.xml --evidence-actions
netrecon scan.xml --evidence-actions --format json
```

The Action Plan reuses the existing Evidence Planner and evidence collector command builder. Requests for the same host, port, and protocol are grouped into one proposed Nmap command, while the fixed purposes explain why each evidence source is useful. Text output shows a human-readable suggested collection command; JSON preserves the exact command as an argv array rather than a shell string. The mode only proposes actions: it does not execute Nmap, infer vulnerabilities, assign risk, or claim that `Actions: 0` means a host is safe or fully assessed.

Real field validation on `main` used `stage-a-discovery.xml` and `windows-smb-detail.xml`. The discovery scan's four Evidence Gaps were grouped into exactly two actions: one SMB action on `445/tcp` for `smb-protocols,smb2-security-mode`, and one HTTP action on `5357/tcp` for `http-title,http-methods`. Text and JSON outputs preserved the same hosts, endpoints, scripts, purposes, and commands. The detailed SMB scan produced `Actions: 0`, confirming that existing real host-level SMB evidence does not create redundant collection actions.
