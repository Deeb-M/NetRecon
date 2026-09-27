# NetRecon Development Handoff

Last updated: 2026-09-26
Repository: Deeb-M/NetRecon
Branch: main

## Verified checkpoint

NetRecon **v0.1.0** remains the project's first public **Alpha pre-release** and an immutable historical release checkpoint.

Release:
- Tag: `v0.1.0`
- Release title: `NetRecon v0.1.0`
- Tagged commit: `1749fcfc0d7ee66baf44ece08ef6b791413ccb4f`
- Release type: Pre-release
- License: MIT
- Supported Python versions validated by CI: 3.10, 3.11, 3.12, 3.13, 3.14
- Release assets: no separately uploaded assets; GitHub provides the source archives for the tag
- The published tag must not be moved to include later development changes

The release itself was published with a verified **379-test** baseline.

Post-release development on `main` has continued deliberately. The latest user-run full regression suite passed:

```text
Ran 395 tests in 0.096s

OK
```

The authoritative continuation point for current development is therefore **main with 395 tests passing**, while `v0.1.0` remains the historical release snapshot.

## Current project phase

The systematic regression-expansion phase and Product Readiness work for **v0.1.0** are complete.

Post-release work has begun with focused CLI/Product UX and documentation improvements. Do not add tests merely to increase the test count. Future development should remain deliberate, evidence-driven, and compatible with the evidence-first design.

NetRecon remains an **Alpha** project. Core functionality is stable and covered by automated tests, while the Intelligence layer remains under active development.

## v0.1.0 readiness completed

The first public release milestone includes:

- Installable Python package with the `netrecon` CLI entry point
- Standard installation documented through a virtual environment
- Clean source distribution and universal Python wheel builds
- SPDX MIT package metadata and project URLs
- MIT `LICENSE` with Deeb Mzareb attribution
- `CONTRIBUTING.md`
- `SECURITY.md`
- GitHub Private Vulnerability Reporting enabled
- GitHub Actions covering Python 3.10 through 3.14
- Safe reproducible example scan data
- Repository description and cybersecurity-related topics
- Annotated Git tag `v0.1.0`
- Public GitHub pre-release `NetRecon v0.1.0`

## Post-release work completed on main

### CLI/Product polish

- Added `netrecon --version`, sourced from installed package metadata rather than a duplicated hard-coded version.
- Added a focused CLI regression test verifying that `--version` exits successfully and reports `netrecon 0.1.0` without requiring a scan.
- Improved the CLI description so it accurately describes analysis, comparison, evidence-based findings, and exposure summaries.
- Corrected `compare_scan` help text so it explicitly applies to both `--diff` and `--analysis-diff`.
- Added a focused regression test for the improved help text.

### New-user installation and UX validation

A clean user-style installation was tested outside the development repository on Kali with Python 3.14.6.

Verified:
- Fresh clone succeeded.
- Virtual environment installation with `python -m pip install .` succeeded.
- Built/installed package version was `0.1.0`.
- Installed `netrecon` CLI worked independently of the source repository.
- `--help`, safe sample parsing, evidence-based analysis, and JSON output worked.
- Missing scan, missing file, malformed XML, non-Nmap XML, incomplete `--diff`, and incomplete `--analysis-diff` produced controlled CLI errors.

This validation identified product/documentation issues rather than scanner or Intelligence failures. The actionable CLI help/version issues have been corrected.

A second clean new-user release-path validation was then completed after the installation documentation change. From a separate `~/netrecon-new-user` directory, the repository was cloned fresh and `git checkout v0.1.0` correctly resolved to tagged commit `1749fcf` in detached-HEAD state. A new virtual environment was created and `python -m pip install .` successfully built and installed `netrecon-0.1.0-py3-none-any.whl`.

The installed release was then exercised from `/tmp`, outside the repository. Verified:
- `netrecon --help` worked from the installed environment.
- Python package metadata reported exactly `0.1.0`.
- `examples/sample.xml` parsed successfully.
- `--analyze` produced the expected conservative INFO finding for missing HTTP product identification.
- `--analyze --format json` produced structured scan, summary, host-summary, and finding data with `evidence_source: service:detection`.
- Running with no scan produced a controlled argparse error.
- A missing scan file produced a clean `scan file not found` error.
- Malformed XML produced a clean `invalid Nmap XML` error.
- Valid non-Nmap XML produced `XML root is not <nmaprun>`.
- `--diff` without a second scan produced a controlled error.
- `--analysis-diff` without a second scan produced a controlled error.
- No Python traceback appeared in these user-error paths.

This confirms that the documented `v0.1.0` installation path installs and runs the exact published release independently of the development checkout.

### Safe comparison examples

Added:
- `examples/before.xml`
- `examples/after.xml`

The pair uses the documentation-only TEST-NET address `192.0.2.10` and the same `tcp:8080` scan coverage in both files.

The before scan identifies `http` without a product. The after scan identifies `http` with product `Apache httpd`.

Manual end-to-end validation passed:

`--diff`:
- Reports one `CHANGED` exposure.
- Shows `http -> http Apache httpd`.
- Reports identical before/after coverage: `tcp:8080`.
- Does not manufacture a coverage change.

`--analysis-diff`:
- Reports one `NO_LONGER_OBSERVED` informational finding.
- Correctly identifies that the previous `Service lacks product identification` finding is no longer observed after product evidence is collected.
- Preserves evidence-first semantics and does not infer a vulnerability.

The README now documents both safe comparison commands.

### Release versus development installation

A new-user documentation issue was confirmed after post-release commits accumulated on `main`:

- `v0.1.0` still points to tagged commit `1749fcf`.
- `main` is intentionally ahead of that release.
- A plain `git clone` therefore installs current development code, not the exact published release.

The README installation instructions now explicitly check out `v0.1.0` for the current public release:

```bash
git clone https://github.com/Deeb-M/NetRecon.git
cd NetRecon
git checkout v0.1.0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

The README separately explains that users who want the latest development version should remain on `main`.

The clean release-path test also confirmed that `v0.1.0` contains only `examples/sample.xml`; the later `examples/before.xml` and `examples/after.xml` comparison pair exists only on post-release `main`. The README was therefore corrected again to label those comparison examples explicitly as development-`main` examples so release users are not instructed to run files that do not exist in `v0.1.0`.

Do not move or retag `v0.1.0` to include post-release work.

## Completed test coverage

Direct or substantial regression coverage exists for:

- Nmap XML parsing and normalization
- CLI behavior and error handling
- Core analyzer orchestration
- Service-derived security analysis
- NSE-derived HTTP, SSH, TLS/certificate, and SMB analysis
- Host summaries
- Network and shared-service summaries
- Analysis summaries and severity ordering
- Exposure diff behavior and scan coverage semantics
- Analysis diff behavior and evidence provenance
- Text and JSON reporters

`models.py` and `findings.py` are primarily immutable dataclass definitions and do not need artificial tests that merely verify Python stores fields.

## Regression rule

Before changing production behavior:

1. Inspect the relevant production code and existing tests.
2. Search for exact and semantic duplicate tests.
3. Add a regression test when a bug, new behavior, or meaningful uncovered branch justifies it.
4. Make the smallest justified production change.
5. Run the full suite:
   ```bash
   git pull && python3 -m unittest discover -s tests -v
   ```
6. Preserve the evidence-first design and avoid speculative vulnerability claims.

The current verified development baseline is **395 tests passing**.

## Evidence Planner milestone

Post-release development has begun moving NetRecon toward a broader evidence-orchestration architecture.

Product direction:

Nmap discovers the network. NetRecon decides what evidence to collect, turns it into intelligence, and shows the analyst what deserves attention.

Intended flow:

Target -> Discovery -> Normalized Service Inventory -> Evidence Planner -> Evidence Collection -> Existing Analyzer / Intelligence -> Analyst Workflow

The first Evidence Planner implementation is now present in evidence_planner.py.

Current behavior:
- EvidenceRequest preserves port, protocol, and NSE script_id.
- plan_evidence_requests() creates structured per-port evidence requests.
- plan_evidence() remains a compatibility/simple view returning script IDs.
- Only open services are considered.
- Evidence already present on a specific port is not requested again.
- Evidence present on one port does not suppress collection on another port.
- SSH maps to ssh2-enum-algos.
- HTTP maps to http-title and http-methods.
- HTTPS composes HTTP evidence with ssl-cert and ssl-enum-ciphers.
- SMB (microsoft-ds or smb) maps to smb-protocols and smb2-security-mode.
- Open 445/tcp with no identified service uses SMB as a conservative port-based fallback.
- Explicit service identification on port 445 takes precedence over the SMB fallback.
- Multiple ports requesting the same NSE script remain separate structured requests; do not globally deduplicate them and lose port context.

Planning principle:

The Evidence Planner should request evidence only when NetRecon already knows how to interpret that evidence.

Important architectural boundary:

NetRecon does not yet execute Nmap or NSE automatically. Do not jump directly to subprocess/Nmap execution. Continue developing and validating the planning contract first. A future orchestration layer should consume structured EvidenceRequest objects rather than infer targets from a flat script list.

Local Nmap/XML scan artifacts generated in the repository root are ignored through /*.xml. This deliberately does not ignore XML files in subdirectories, allowing intentional fixtures such as tests/fixtures/*.xml to remain versioned.

## Next development direction

Treat `v0.1.0` as the stable historical Alpha release checkpoint and current `main` as post-release development.

Future work should focus on meaningful Intelligence-layer improvements, bug fixes, documentation, or release-driven enhancements rather than increasing the test count for its own sake.

Potential release-process improvement identified during validation: future releases can consider attaching the built `.whl` and source distribution `.tar.gz` as explicit GitHub Release assets. This is not a current defect and was not required for `v0.1.0`.

Any production change after `v0.1.0` belongs to post-release development and should preserve compatibility unless a change is intentionally documented.

## Working method

NetRecon is not a Codex project. Work through the GitHub connector and the user's local Kali environment.

Prefer one meaningful change at a time. Explain what is being changed, why it matters to the project, and how it should be verified locally.

Do not use a fixed test target as a development goal. Tests are a safety net for meaningful behavior, not the product itself.

## Real-world v0.1.0 field validation (2026-09-25 to 2026-09-26)

A long, controlled real-world validation phase was completed against the exact published `v0.1.0` release from a separate clean checkout in `~/netrecon-new-user/NetRecon`. The purpose was to test the complete chain **real target -> Nmap 7.99 -> XML evidence -> NetRecon**, not merely synthetic unit fixtures.

Authorized lab:
- Kali host: `192.168.227.128`
- Windows 10 lab host: `192.168.227.140`
- VMware lab network: `192.168.227.0/24`
- VMware infrastructure addresses were deliberately not explored further.
- Temporary services/configurations were restored after each experiment and cleanup was verified.

### Capabilities exercised successfully

Real scans substantially exercised:
- Windows service discovery: RPC, NetBIOS, SMB, Microsoft HTTPAPI.
- Multi-host parsing and summaries without evidence mixing.
- SMB protocol/signing evidence and conservative findings.
- HTTP title/default-page/method evidence.
- SSH service context and algorithm inventory.
- TLS certificate expiry, not-yet-valid, identity mismatch, protocol-version evidence.
- Telnet exposure plus product-unknown evidence.
- JSON reporting and evidence provenance.
- Exposure Diff and Analysis Diff.
- Port state transitions (open/filtered), newly open/no-longer-open behavior.
- Scan-scope changes without false exposure changes.
- Host newly observed/not observed behavior.
- Service identity/version changes.
- Finding lifecycle behavior when the same evidence source is recollected and a condition disappears.

Important evidence-first behavior was confirmed: when application evidence is not recollected, NetRecon does not falsely mark an application-context finding as resolved.

### Production rule coverage status

Real-world validated or substantially exercised:
- `host.platform.context`
- `service.application.context`
- `service.smb.exposed`
- `service.netbios.exposed`
- `service.rpc.exposed`
- `service.telnet.exposed`
- `service.product.unknown`
- `http.default_page.detected`
- `http.methods.review`
- `ssh.algorithms.inventory`
- `tls.certificate.identity_mismatch`
- `tls.certificate.expired`
- `tls.certificate.not_yet_valid`
- `tls.protocol.legacy_enabled`
- modern SMB protocol reporting
- `smb.signing.review`

Deliberately not forced merely for coverage:
- `service.ftp.exposed`: no FTP server was installed just to exercise a simple exposure rule.
- SMB1 reporting: SMBv1 was not enabled solely for testing.
- `tls.key_exchange.anonymous`: a controlled ADH attempt was made, but Apache/mod_ssl rejected the selected anonymous cipher at runtime with `no cipher match`. The environment was restored. This rule remains **not field-validated**, not failed.

### Confirmed real-world v0.1.0 gaps

Two concrete compatibility/parsing gaps were reproduced with real Nmap 7.99 evidence and should be the first post-validation fixes.

#### 1. HTTP directory listing compatibility

Real Nmap `http-title` output for an exposed directory was:

`Index of /netrecon-directory-test`

NetRecon v0.1.0 did not emit `http.directory_listing.exposed` because the production rule only recognizes output beginning with:

`Directory listing for `

This is a real Nmap-output compatibility gap. Add a focused regression test based on the observed `Index of ...` form, then make the smallest conservative rule change.

#### 2. HTTP read-only methods parsing

A controlled Apache path was restricted to GET/HEAD. Nmap 7.99 produced:

`Supported Methods: GET HEAD`
`Path tested: /netrecon-readonly/`

NetRecon v0.1.0 did not emit `http.methods.standard_read_only`.

Root cause was identified in `nse_rules.py`: after flattening script output, method parsing takes everything after `Supported Methods:` until `Potentially risky methods:` when that marker exists. For a GET/HEAD-only result there is no risky-method marker, so `Path tested:` and the path are incorrectly consumed as method tokens. The resulting set is no longer a subset of `{GET, HEAD}`.

The WebDAV/review branch worked because its Nmap output contained `Potentially risky methods:`, which already acts as a terminator before `Path tested:`.

Add a regression test using the observed Nmap 7.99 output structure and fix parsing so metadata after the supported-method list is not treated as HTTP methods.

### Other capability gaps / future Intelligence candidates observed

These are ideas/capability gaps, not necessarily bugs and not commitments to implement immediately:
- Nmap OS fingerprint data is not currently mapped into NetRecon's model/report/JSON. Real Linux and Windows `-O` scans demonstrated this.
- `smb2-capabilities` evidence is preserved but could support richer semantic extraction.
- `nbstat` identity evidence could support a conservative Host Identity capability.
- Empty NSE script presentation could be cleaned up.
- Raw NSE changes such as HTTP title changes are preserved in scan evidence but are not necessarily represented as semantic Analysis Diff changes.
- SSH `ssh-auth-methods` evidence is preserved but has no dedicated Intelligence rule.
- SSH host-key intelligence can be considered when usable evidence is present.
- TLS identity output showed duplicate hostname presentation in one test (`Names: netrecon-lab.local, netrecon-lab.local`), suggesting a possible normalization/deduplication improvement.

Do not implement these merely because they were noticed. Apply the regression rule and prioritize evidence-backed analyst value.

## Product direction decided after field validation

The field-testing phase raised the central product question: **if Nmap is already powerful, why should an analyst use NetRecon in addition to Nmap?**

The answer adopted for future development is that NetRecon must not become merely "Nmap with prettier output" and should not try to reimplement Nmap.

### Product role

Nmap remains the scanning/discovery engine and source of raw network evidence. NetRecon should become an **analyst/intelligence layer above Nmap**, with optional scan orchestration.

Working product statement:

> **Nmap discovers the network. NetRecon decides what evidence to collect, turns it into intelligence, and shows the analyst what deserves attention.**

A useful mental model is:
- **Nmap = discovery / collection engine**
- **NetRecon = orchestration + normalization + intelligence + analyst workflow**

Nmap XML remains the preferred evidence interface. NetRecon should preserve the exact scanner command, raw evidence, provenance, and analyst traceability rather than becoming a black box.

### Why orchestration alone is not enough

A major user need identified during field testing is avoiding the need to remember many Nmap flags, NSE scripts, script arguments, and repeated command variations throughout routine work.

A future NetRecon UX may let the analyst express **intent** instead of manually constructing Nmap syntax, for example conceptually:

`netrecon assess <target>`
`netrecon assess <target> --profile web`
`netrecon assess <target> --profile tls`

NetRecon could then select a transparent, conservative set of Nmap checks, collect XML, analyze it, and produce one focused report.

However, this must not become only a profile/command frontend. Nmap's own Zenmap already provides saved scan profiles, command construction, result storage, aggregation, and scan comparison. NetRecon therefore needs differentiated analyst value **after collection**: structured evidence, normalization, correlation, findings, summaries, lifecycle/history, evidence-aware diffing, and prioritization of what deserves review.

### Long-term product shape

Potential product flow:

`Target -> NetRecon intent/profile -> Nmap -> XML evidence -> NetRecon Intelligence -> analyst report`

The analyst should be able to see:
- what profile/intention was selected;
- exactly which Nmap command(s) and NSE scripts ran;
- the raw XML/evidence;
- normalized hosts/services;
- evidence-backed findings and recommendations;
- what changed since a previous assessment;
- eventually, longer-term first-seen/last-seen/history and cross-scan correlation.

This preserves usefulness for beginners without taking control away from advanced Nmap users.

### Development decision rule

For every proposed feature, ask:

> **What does NetRecon do with Nmap evidence that an analyst should not have to do manually?**

If the answer is only "Nmap already displays this", the feature is probably not differentiated enough.

Strong candidates are features that save manual:
- scan selection/orchestration;
- normalization;
- evidence correlation;
- comparison;
- historical tracking;
- interpretation;
- prioritization;
- report construction.

Keep the evidence-first rule: NetRecon may explain and organize observed evidence, but must not manufacture vulnerabilities or certainty that Nmap did not establish.

### Development sequencing

Do **not** jump directly into a large profile/orchestration system.

Next sequence:
1. Preserve this field-validation/product-direction checkpoint.
2. Fix the two confirmed Nmap 7.99 HTTP gaps one at a time, each with a focused regression test and the smallest justified production change.
3. Run the full suite after each meaningful change.
4. Keep `v0.1.0` immutable.
5. After the confirmed gaps are closed and main is stable, design a **small Scan Orchestration proof of concept**, preferably one conservative profile/end-to-end flow before adding multiple profiles.
6. Evaluate every later Intelligence idea against analyst value rather than test-count growth or feature count.

The desired proof-of-concept chain is:

`Target -> NetRecon -> Nmap -> XML -> NetRecon Intelligence -> Report`

Only expand to Web/TLS/SSH/SMB/etc. after the first flow proves useful, transparent, and maintainable.

## Chat handoff checkpoint — 2026-09-26

The extended v0.1.0 field-testing chat is complete. Continue future work from this document rather than reconstructing the testing history from chat.

At chat close:
- published `v0.1.0` remains immutable at `1749fcf`;
- current development baseline recorded before field testing remains **381/381 tests passing**;
- field tests were performed in a separate clean `v0.1.0` checkout and did not modify production code;
- the main local development repository contains numerous pre-existing untracked XML lab artifacts; do not delete, add, or modify them casually;
- no production fix for the two newly confirmed HTTP gaps has yet been made;
- the next code task should begin with the directory-listing compatibility regression, unless a fresh inspection shows a better dependency/order;
- after that, fix the HTTP GET/HEAD + `Path tested:` parsing regression;
- then reassess the small orchestration proof of concept.

## Evidence Planner checkpoint — 2026-09-26

Development has moved beyond the earlier 381-test field-validation checkpoint.

Current validated baseline:
- **403/403 tests passing locally on Kali**.
- GitHub CI is expected to remain the gate before local synchronization.
- The public `v0.1.0` release remains immutable at `1749fcf`.

### Evidence Planner architecture

The current direction is:

`Target -> Discovery -> Normalized Service Inventory -> Evidence Planner -> Evidence Collection -> Existing Analyzer / Intelligence -> Analyst Workflow`

NetRecon still does **not** execute Nmap/NSE automatically at this checkpoint. The planner contract is being matured before an execution layer is introduced.

The planner follows an evidence-first rule: request only evidence that the existing analyzer already knows how to interpret.

Currently supported service-to-evidence policy:
- SSH -> `ssh2-enum-algos`
- HTTP -> `http-title`, `http-methods`
- HTTPS -> HTTP evidence plus `ssl-cert`, `ssl-enum-ciphers`
- SMB / `microsoft-ds` -> `smb-protocols`, `smb2-security-mode`

### Collection contract

`EvidenceRequest` represents one requested collection action and contains:
- port;
- normalized protocol;
- NSE script ID.

`HostEvidencePlan` binds:
- one target address;
- the tuple of detailed `EvidenceRequest` items still needed for that host.

The target belongs to the host-level plan rather than being duplicated into every request.

### Planner invariants now covered by regression tests

- only open ports generate requests;
- service/state/protocol and existing script IDs are normalized where relevant;
- already-present evidence is not requested again;
- partial evidence produces only the missing requests;
- complete supported evidence produces an empty request tuple while preserving the target;
- the same script required on different ports remains a separate request for each port;
- evidence present on one port does not suppress the same evidence needed on another;
- unsupported services fail closed with no evidence request;
- explicit service identification takes precedence over port fallback;
- port `445/tcp` with no identified service conservatively falls back to SMB evidence;
- whitespace-only service on `445/tcp` is treated as missing and uses that fallback;
- `445/udp` does not trigger the SMB fallback.

### Next development boundary

Do not jump directly to subprocess/Nmap execution.

Before an Evidence Collector is implemented, continue validating the planner/collector boundary only where a concrete execution requirement exists. Avoid adding duplicate tests or speculative fields merely to grow the contract or test count.

When collection is introduced, it should consume a self-contained `HostEvidencePlan`, preserve transparent Nmap command/evidence provenance, and remain separate from analysis/intelligence logic.



## Evidence Collection checkpoint — 2026-09-27

Development has now crossed the earlier planner-only boundary.

Current validated baseline before this documentation checkpoint:
- **439/439 tests passing locally on Kali**.
- GitHub CI is the synchronization gate.
- The public `v0.1.0` release remains immutable at `1749fcf`.

### Implemented collection pipeline

The current end-to-end internal flow is:

`HostEvidencePlan -> CollectionSpec -> NmapCommand -> CollectionResult -> ParsedCollectionResult -> Scan -> Analyzer -> Findings`

The collector now:
- groups requested NSE scripts by target port/protocol;
- builds transparent argv tuples rather than shell command strings;
- uses `shell=False`;
- emits XML to stdout with `-oX -`;
- executes prepared Nmap commands while capturing stdout/stderr and return code;
- preserves non-zero Nmap process results instead of inventing successful evidence;
- parses successful XML directly from memory;
- preserves failed collection outcomes with `scan=None`;
- analyzes only successfully parsed scans;
- supports complete host-plan collection and analysis;
- supports an explicit timeout propagated through the full host pipeline;
- reports a missing Nmap executable and collection timeout through `EvidenceCollectionError`.

No CI regression test executes real Nmap; subprocess execution is mocked.

### Architectural boundary

Nmap execution exists as an isolated internal collection layer, but it is **not yet connected to the CLI or automatic target scanning**.

Do not connect the collector directly to the existing analyzer by replacing the original discovery host with a partial evidence scan. Evidence collection scans may contain only one requested port and would lose discovery context. Before user-facing orchestration, define how collected evidence is merged/correlated with the original normalized host while preserving provenance.

The next meaningful design boundary is therefore evidence correlation/merge, followed by a deliberately small CLI orchestration proof of concept once that contract is stable.

## Stage A — Evidence Collection POC implementation complete — 2026-09-27

Stage A has reached its implementation exit criteria and is ready for controlled Kali field validation.

Validated development baseline:
- **483/483 tests passing locally on Kali**.
- GitHub CI is green for the 483-test checkpoint.
- Public `v0.1.0` remains the immutable historical Alpha release at `1749fcf`.
- These changes are post-release development on `main`; no new public release has been published yet.

Implemented end-to-end POC flow:

`Discovery XML -> normalized Host -> Evidence Planner -> targeted Nmap/NSE collection -> in-memory XML parsing -> evidence correlation -> existing Analyzer -> Findings -> text/JSON report`

Stage A capabilities:
- `netrecon <scan.xml> --collect-evidence` is wired to the real planner/collector pipeline.
- Collection is restricted to evidence NetRecon already knows how to interpret.
- Prepared Nmap commands use argv tuples with `shell=False` and XML stdout via `-oX -`.
- Discovery host/service metadata remains authoritative while collected NSE evidence is merged into matching discovered ports.
- Host and port correlation guards prevent evidence from being merged into the wrong discovery context.
- Equivalent IPv6 representations are handled during host correlation.
- Failed Nmap commands are preserved as failed outcomes; successful evidence from other collection units can still be correlated and analyzed.
- Missing Nmap and subprocess timeout failures are surfaced as controlled `EvidenceCollectionError` paths.
- CLI collection has a bounded per-command timeout: 60 seconds by default, configurable with `--evidence-timeout`; non-positive values are rejected.
- A process that exits zero but returns invalid Nmap XML is preserved as a failed collection outcome rather than crashing the pipeline.
- Text and JSON evidence-collection reports include collection status, failures, and correlated findings.
- Multi-host JSON is emitted as one valid JSON document.
- JSON collection errors preserve already completed host results.
- CI tests mock subprocess execution; CI does not run real Nmap.

### Stage A exit decision

Do not continue adding unit tests merely to extend the test count before field validation.

The implementation POC is complete enough for the next required activity: a controlled real-world Kali field test. The field test is now the source of evidence for Stage B hardening work.

### Stage A field-test goals

Validate the actual chain with authorized lab targets and real Nmap:
1. Start from a real discovery XML file.
2. Run `--collect-evidence` in text mode.
3. Confirm the planner requests only justified NSE evidence for discovered services.
4. Confirm the real Nmap commands execute and XML stdout parses correctly.
5. Confirm collected evidence is correlated back to the correct host and port.
6. Confirm resulting findings are visible to the analyst.
7. Repeat in JSON mode and verify one valid machine-readable document.
8. Exercise at least one controlled failure/partial-result path where practical.
9. Record real-world incompatibilities as Stage B evidence; do not redesign the system during the test.

### Stage B boundary

Stage B is **Evidence Collection Hardening** and begins only after the Stage A field test.

Stage B work should be driven by observed field behavior: real Nmap output compatibility, permissions, timing, unreachable/filtered targets, partial results, multi-host behavior, and operator UX. Do not preemptively implement speculative hardening before collecting that evidence.



## Stage A Field Validation Closure — 2026-09-27

Stage A — Evidence Collection POC is field-validated and closed.

Real Kali/Windows lab validation:
- Kali executed the current NetRecon CLI against discovery XML for authorized Windows target `192.168.227.138`.
- Discovery identified `135/tcp msrpc`, `139/tcp netbios-ssn`, `445/tcp microsoft-ds`, and `5357/tcp http`.
- Live process observation confirmed targeted collection commands for:
  - `445/tcp -> smb-protocols,smb2-security-mode`
  - `5357/tcp -> http-title,http-methods`
- Manual Nmap validation showed the Windows host returns host-level SMB NSE evidence:
  - modern SMB dialects `2.0.2, 2.1, 3.0, 3.0.2, 3.1.1`
  - SMB signing enabled but not required.
- Field testing exposed a real correlation gap: host-level NSE scripts were parsed but were not merged into the discovery host. This was fixed in commits `e33d733` / `554e48e`, with regression test 484.
- After reinstalling the updated checkout with `python -m pip install .`, the real end-to-end run produced 6 findings, including:
  - `smb.signing.review`
  - `smb.protocol.modern_only`
- JSON mode also returned the same 6 findings with `status: complete` and no failures.

Important field-test workflow lesson:
- A `git pull` updates the checkout but does not reinstall the already-built CLI package in the active virtual environment. Field validation of the installed `netrecon` command must reinstall the checkout after relevant code changes (for example, `python -m pip install .`).

Stage A exit decision:
- The POC is proven end-to-end in a real lab:
  `Discovery XML -> Evidence Planner -> targeted Nmap/NSE -> XML stdout -> Parser -> Correlation -> Analyzer -> Text/JSON Reporter`.
- Stage A is closed at the 484-test regression baseline.
- Do not add more Stage A tests merely to increase the count.

### Stage B entry finding — timeout hardening

The first controlled failure test used `--evidence-timeout 0.001` and produced:
`Error: Nmap evidence collection timed out`.

This demonstrates the first Stage B hardening gap:
- `subprocess.TimeoutExpired` currently becomes `EvidenceCollectionError` immediately.
- A timed-out collection command therefore aborts the collection instead of being preserved as a failed outcome.
- Stage B should make per-command timeout a reportable collection outcome where practical, continue later evidence commands, preserve already completed evidence, and report a partial result rather than losing the collection context.
- The implementation must remain conservative: no shell execution, no fabricated evidence, and timeout/failure state must be explicit to the analyst.

Stage B should be driven by real failure behavior (timeouts, non-responsive targets, partial results, Nmap failures, UDP/privilege behavior, and multi-host behavior), followed by a second field test.


## Stage B — Evidence Collection Hardening checkpoint — 2026-09-27

Stage B implementation hardening has reached the next field-test boundary.

Validated development baseline:
- **505/505 tests passing locally on Kali**.
- GitHub CI is green at commit `0bf0e3d`.
- Stage A remains closed and field-validated; no new public release has been published.

Hardening completed since the Stage A field test:
- Per-command timeout is preserved as an explicit failed collection outcome (synthetic return code 124) instead of aborting the entire host collection.
- Collection continues after a timed-out command so later evidence can still be collected and correlated.
- Text and JSON CLI paths preserve/report partial evidence results.
- Non-zero command outcomes cannot be accepted as successful evidence even if stdout resembles XML.
- A zero exit with invalid XML is reported explicitly as `Nmap returned invalid XML`.
- `--evidence-timeout` rejects non-positive and non-finite values.
- Evidence grouping normalizes protocol and script IDs, deduplicates script IDs while preserving order, and rejects blank scripts, unsupported/blank protocols, and ports outside 1..65535.
- Evidence targets are normalized and blank targets are rejected at both planning and collection boundaries.

### Stage B checkpoint decision

Stop adding unit tests merely to increase the count. The next meaningful activity is the **second controlled field test** against the authorized lab target. It should exercise the hardened normal path and partial/failure behavior with real Nmap. Any new Stage B implementation after this checkpoint should be driven by observations from that field test.


## Stage B Field Test #2 — validated — 2026-09-27

The second controlled field test validated the Stage B hardening against the authorized Windows lab target `192.168.227.138`.

Observed real behavior:
- Normal collection remained compatible and returned `Status: complete` with the same 6 findings validated in Stage A.
- A `0.001` second per-command timeout produced `Status: partial` rather than aborting the CLI, preserved the 4 discovery-derived findings, and reported two independent collection failures.
- JSON mode preserved the same partial status, two failures, and 4 findings in one valid document.
- A `0.75` second timeout produced a real mixed partial result on one run (one collection unit timed out while another completed), proving continuation after a real per-command timeout. The same threshold was timing-sensitive and could also complete on a later run, so it must not be treated as deterministic.
- Field testing exposed an analyst-UX gap: timeout failures originally did not identify which evidence command failed.
- Regression test 506 and implementation commit `0f110c1` fixed that gap. A repeated `0.001` field run then reported:
  - `445/tcp` with `smb-protocols,smb2-security-mode`
  - `5357/tcp` with `http-title,http-methods`
  as distinct timed-out Nmap commands.
- The validated regression baseline is **506/506 tests passing**, with GitHub CI green.

Stage B exit decision:
- The field-derived timeout/partial-result hardening is proven end-to-end.
- Stop adding Stage B tests merely to increase coverage count.
- Stage B — Evidence Collection Hardening is closed.
- The next milestone is **Stage C — Intelligence Workflow**, connecting the proven evidence pipeline more deeply to analyst-facing Network/Host Summary, prioritization, and workflow.


## Stage C — Intelligence Workflow checkpoint — 2026-09-27

Stage C has begun with a deliberately descriptive, evidence-first host intelligence summary. No arbitrary risk score has been introduced.

Validated development baseline:
- **508/508 tests passing locally on Kali**.
- GitHub CI is green at commit `4ffeef4`.
- Stage B remains closed; Stage C builds on the proven collection/correlation pipeline.

Completed Stage C work:
- `HostSummary` now preserves per-host finding severity counts in deterministic order.
- Severity labels are normalized before counting; known severities use the established order and unknown severities remain visible rather than being discarded.
- Analysis JSON exposes the same per-host `severity_counts` through the existing `host_summaries` envelope.
- Text analysis now has a dedicated `Host Summary` section. It is kept separate from the raw scan renderer so observations and intelligence remain distinct.
- `netrecon <scan.xml> --analyze` now presents the workflow as:
  `Scan observations -> Host Summary -> prioritized Findings`.
- Hosts with no findings remain explicit and descriptive (`Severity: none`); collection completeness is not converted into security severity.

### Stage C Field Validation #1

The installed CLI was refreshed in the dedicated field-test checkout and run against the existing authorized Windows discovery scan `stage-a-discovery.xml` for `192.168.227.138`.

Observed output:
- 4 open ports and 4 normalized services.
- Host Summary reported 4 findings with `info=4`.
- The four discovery-derived findings remained the same platform/RPC/NetBIOS/SMB informational findings.
- The summary therefore reflected the evidence actually present in the discovery XML and did not imply the richer SMB conclusions that require targeted collection.

Stage C checkpoint decision:
- The first analyst-facing Host Summary is useful and field-valid on discovery-only evidence.
- The next meaningful question is whether the same analyst summary remains useful after targeted evidence collection, where richer evidence-backed findings such as SMB signing/protocol findings are available.
- Do not add a risk score. Keep collection completeness and security severity as separate dimensions.


### Stage C Field Validation #2 — correlated evidence workflow

The dedicated field-test checkout was updated through commit `0a43d29`, the installed package was rebuilt, and the authorized Windows lab target `192.168.227.138` was tested with:
`netrecon stage-a-discovery.xml --collect-evidence`.

Observed output:
- Evidence collection completed successfully.
- The correlated Host Summary retained the 4 discovered open ports and normalized services.
- Findings increased from the discovery-only 4 informational findings to 6 evidence-backed findings.
- Severity distribution became `medium=1, info=5`.
- The medium finding was `SMB signing configuration requires review`, backed by real `smb2-security-mode` evidence that message signing was enabled but not required.
- The additional informational finding recorded the modern SMB dialects returned by `smb-protocols`.
- The analyst-facing flow is now:
  `Evidence Collection status -> correlated Host Summary -> prioritized Findings`.

Validation decision:
- The Host Summary remains useful after targeted evidence collection and accurately reflects the richer correlated evidence.
- No extra Nmap execution or duplicate analysis is needed to render it; the report reuses the already-correlated host and findings.
- Keep collection completeness separate from finding severity.
- The next Stage C design question is multi-host analyst attention: how to make existing per-host evidence and severity distributions easier to triage at network scope without inventing a numeric risk score.


### Stage C checkpoint — analyst attention ordering and evidence JSON parity

The Stage C host intelligence contract has been extended without introducing a numeric risk score.

Validated development baseline:
- **510/510 tests passing locally on Kali**.
- Multi-host Host Summary ordering is deterministic and driven only by the highest observed finding severity:
  `critical -> high -> medium -> low -> info -> no findings`.
- Hosts at the same attention level are ordered by host address; finding count is deliberately not used as hidden risk weighting.
- Analysis JSON `host_summaries` preserves the same analyst-attention ordering as the text/model path.
- A proposed separate Network Attention Summary was not added because the existing Analysis Summary already carries network-level finding counts and severity distribution; duplicating those numbers would not add analyst value.

Evidence Collection JSON parity:
- Evidence Collection JSON now includes a `host_summary` built from the already-correlated host and findings.
- The JSON summary exposes host status, open-port count, normalized services, finding count, and severity counts.
- This reuses the same `summarize_hosts()` logic as the analyst-facing text/analysis JSON rather than creating a parallel intelligence implementation.
- Collection status (`complete` / `partial`) remains separate from finding severity.

### Stage C Field Validation #3 — Evidence Collection JSON

The dedicated field-test checkout was updated through commit `f464aa4`, reinstalled, and tested against the existing authorized Windows lab target `192.168.227.138` with:
`netrecon stage-a-discovery.xml --collect-evidence --format json`.

Observed real output:
- collection `status: complete`
- `failures: []`
- correlated `host_summary` reported 4 open ports
- normalized services: `http`, `microsoft-ds`, `msrpc`, `netbios-ssn`
- 6 findings
- severity distribution: `medium=1, info=5`
- `smb.signing.review` remained the medium finding and was explicitly backed by `nse:smb2-security-mode` evidence that SMB signing was enabled but not required.
- `smb.protocol.modern_only` remained backed by `nse:smb-protocols`.

Validation decision:
- Text and JSON evidence-collection workflows now expose the same correlated host intelligence.
- The field result exactly matches the previously validated text workflow: 4 open ports, 6 findings, `medium=1, info=5`.
- The summary does not create severity from collection state; evidence completeness and security findings remain independent dimensions.
- Do not add more summary layers merely to repeat existing severity counts. Future Stage C work should be driven by a distinct analyst workflow need.


### Stage C SSH field-validation checkpoint

A controlled local field validation confirmed the SSH evidence workflow against the Kali host.

Observed behavior:
- A real service-discovery XML identified one open SSH service on localhost.
- NetRecon selected and collected the SSH algorithm inventory required by the existing evidence plan.
- Evidence collection completed successfully.
- Host Summary reported one open SSH port and three informational findings: platform context, application context, and SSH algorithm inventory.
- The newly added legacy-KEX review finding was not emitted because the configured SSH service did not offer either of the two KEX methods covered by that rule.
- This validates the negative path against real service output and demonstrates that the new rule does not flag the tested modern configuration.

Validation decision:
- The SSH workflow is now field-validated through discovery, evidence planning, collection, parsing, correlation, analysis, and Host Summary.
- Keep the first SSH intelligence rule deliberately narrow; do not generalize it into a broad vulnerability claim.
- Development regression baseline is 511/511 tests passing locally on Kali.

### Stage C Combined Analyst Diff checkpoint

Stage C now includes a combined analyst comparison workflow through `--combined-diff`.

The workflow composes the existing exposure and analysis comparison engines rather than introducing a third comparison model:

- `Exposure Changes` continues to describe observed network/service exposure changes.
- `Analysis Changes` continues to describe evidence-based finding changes.
- Text output keeps both sections visibly separate.
- JSON uses a `change_type: combined` envelope with independent `exposure` and `analysis` objects.
- Existing `--diff` and `--analysis-diff` behavior remains available and unchanged.
- No combined risk score or hidden weighting is introduced.

Regression baseline after the implementation: **513/513 tests passing locally**, with GitHub CI green for the implementation commit.

Real field validation used the existing Kali Telnet scans `kali-telnet-real.xml` and `kali-telnet-after.xml`.

Observed text result:

- Exposure summary: `NO_LONGER_OPEN=1` for `192.168.227.128:23/tcp telnet`.
- Analysis summary: `NO_LONGER_OBSERVED=2`.
- The removed findings were the informational missing-product finding and the medium Telnet exposure finding.
- Both scans covered `tcp:23`; coverage was unchanged, with no newly scanned or no-longer-scanned ports.

This is an important semantic validation: NetRecon distinguished **a previously open Telnet service becoming no longer open** from **Telnet merely disappearing because port 23 was no longer scanned**.

The same field pair was validated with `--combined-diff --format json`. The JSON preserved:

- top-level `change_type: combined`;
- separate machine-readable `exposure` and `analysis` sections;
- exposure and finding change details;
- finding evidence provenance;
- unchanged coverage metadata in both sections.

This closes the first real field-validation checkpoint for the Combined Analyst Diff workflow.

