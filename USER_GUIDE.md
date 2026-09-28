# NetRecon User Guide

This guide explains how to choose and use NetRecon's main workflows. NetRecon analyzes Nmap XML and can also orchestrate bounded evidence collection against systems you are authorized to test.

## Choose the workflow

Use an existing Nmap XML file when you already have scan evidence:

- `netrecon scan.xml` — summarize the scan.
- `netrecon scan.xml --analyze` — add conservative evidence-based findings.
- `netrecon scan.xml --attention` — show findings that warrant analyst review.
- `netrecon before.xml after.xml --diff` — compare exposure.
- `netrecon before.xml after.xml --analysis-diff` — compare evidence-based findings.
- `netrecon before.xml after.xml --combined-diff` — show both comparison views.
- `netrecon scan.xml --evidence-gaps` — show supported evidence still missing.
- `netrecon scan.xml --evidence-actions` — preview collection actions without executing them.
- `netrecon scan.xml --collect-evidence` — collect targeted evidence for services already present in the scan.
- `netrecon --history scan1.xml scan2.xml [...]` — summarize endpoint history.
- `netrecon --finding-history scan1.xml scan2.xml [...]` — summarize finding history.

Use a target when NetRecon should start with Nmap discovery:

- `netrecon --discovery-plan TARGET` — preview baseline discovery.
- `netrecon --discover TARGET` — run baseline discovery.
- `netrecon --investigate TARGET` — discover and show planner-supported next evidence actions.
- `netrecon --investigate-collect TARGET` — run the bounded investigation workflow.

## Installation

NetRecon requires Python 3.10 or newer. Nmap must also be installed for workflows that perform discovery or evidence collection.

```bash
git clone https://github.com/Deeb-M/NetRecon.git
cd NetRecon
git checkout v0.2.0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
netrecon --version
netrecon --help
```

Commands that only analyze existing XML do not launch Nmap.

## First XML analysis

```bash
nmap -sV -oX scan.xml <authorized-target>
netrecon scan.xml
netrecon scan.xml --analyze
netrecon scan.xml --analyze --format json
```

## Comparing scans

```bash
netrecon before.xml after.xml --diff
netrecon before.xml after.xml --analysis-diff
netrecon before.xml after.xml --combined-diff
```

NetRecon keeps scan coverage separate from exposure and finding changes. Evidence that was not collected is not treated as evidence that an exposure or finding disappeared.

## Evidence planning and collection

```bash
netrecon scan.xml --evidence-gaps
netrecon scan.xml --evidence-actions
netrecon scan.xml --collect-evidence
```

`--evidence-actions` previews supported actions without running them. Use `--evidence-timeout SECONDS` to change the per-command collection timeout; the value must be finite and greater than zero.

## Bounded investigation

```bash
netrecon --discovery-plan <authorized-target>
netrecon --investigate <authorized-target>
netrecon --investigate-collect <authorized-target>
netrecon --investigate-collect <authorized-target> --adaptive-plan
```

The workflow can finish as `complete` or `stalled`. A stalled investigation is a valid bounded outcome. It does not mean the target is safe, and missing evidence is not converted into resolution.

## Explicit approval

Some finding-derived requirements are blocked until the analyst approves that exact requirement ID:

```bash
netrecon --investigate-collect <authorized-target> \
  --approve-requirement <requirement-id>
```

The option may be repeated for multiple explicit requirements. Approval is requirement-scoped, not blanket authorization. An attempted-unsatisfied requirement is not silently retried.

## Investigation History and Memory

```bash
netrecon --investigate-collect <authorized-target> \
  --investigation-history investigation-history.jsonl
```

The JSONL file is append-only. On later runs for the same target, NetRecon compares the current terminal synthesis with the latest stored synthesis and reports Investigation Memory. History does not authorize collection and does not turn absence into resolution.

## Reading investigation output

Investigation output may include:

- **Evidence Collection Outcomes** — commands executed and whether requested evidence was observed.
- **Continuation Decision** — whether the controller can continue or must stop.
- **Final Investigation Decision** — canonical terminal state and reason.
- **Investigation Explanation** — Known, Unresolved, Blocked, and Next.
- **Investigation Synthesis** — terminal evidence-aware summary.
- **Investigation Memory** — changes relative to the previous stored synthesis when history is enabled.

Use `--format json` for structured machine-readable output.

## Exit behavior

A completed bounded investigation can exit successfully even when its terminal state is `stalled`. Stalled is a product result, not automatically a CLI execution failure.

Invalid arguments, invalid input, discovery failures that prevent readiness, and history read/write failures can return a non-zero status. Automation should inspect the final structured investigation status rather than assuming exit code zero means every requirement was satisfied.

## Repository examples

```bash
netrecon examples/sample.xml
netrecon examples/sample.xml --analyze
netrecon examples/before.xml examples/after.xml --combined-diff
```

## Help and troubleshooting

```bash
netrecon --version
netrecon --help
nmap --version
```

If XML analysis fails, verify that the input is Nmap XML generated with `-oX`, not normal terminal output. If an Nmap-backed workflow fails, verify Nmap is available in the same environment.

## Responsible use

Use NetRecon only on systems and networks you are authorized to test. Collection is deliberately targeted, bounded, and evidence-driven.
