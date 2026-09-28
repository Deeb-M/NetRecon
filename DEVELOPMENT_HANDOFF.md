# NetRecon Development Handoff

Last updated: 2026-09-28
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



### Stage C Exposure History field-validation checkpoint

The first stateless Exposure History workflow is now field-validated through the installed CLI.

Validated CLI:
`netrecon --history <scan1.xml> <scan2.xml> [scan3.xml ...]`

Real field validation used the existing multi-host scans:
- `lab-multi.xml`
- `lab-multi-after.xml`
- `lab-multi-restored.xml`

Observed history:
- 5 unique open endpoint identities.
- `192.168.227.128:80/tcp` was observed open in the first and third scans only, producing `observations=2`, with first/last observation timestamps taken from the original Nmap XML.
- The middle scan reported that endpoint as `filtered`; History correctly did not count it as an open observation.
- `192.168.227.140:135/tcp`, `:139/tcp`, `:445/tcp`, and `:5357/tcp` were open in all three scans and each produced `observations=3`.
- Text output rendered the observation timestamps in UTC.
- JSON preserved the same five endpoint records and kept `first_seen` / `last_seen` as integer Unix timestamps for machine consumers.

Evidence-first semantic decision:
- History reports only when an endpoint was **observed open** and how many supplied scan documents observed it.
- A missing, filtered, unscanned, or otherwise non-open observation does not justify claims such as “closed”, “reopened”, continuous exposure, or exposure duration.
- History therefore complements Diff rather than replacing it: Diff describes supported state changes between selected scans; History summarizes repeated open observations across multiple scans.

Regression baseline before field validation: **529/529 tests passing**, GitHub CI green through commit `73ad41e`.


### Exposure History observation-opportunity checkpoint

Exposure History now distinguishes an open observation from a valid opportunity to observe the endpoint.

Semantics:
- `observations` counts supplied scan documents in which the endpoint was actually observed `open`.
- `opportunities` counts supplied scans in which the same normalized host was observed `up` and the endpoint's port/protocol was explicitly included in Nmap scan scope.
- A filtered or closed in-scope endpoint can therefore contribute an opportunity without contributing an open observation.
- An out-of-scope port or a host not observed `up` does not contribute an opportunity.
- Only endpoints observed open at least once are emitted by Exposure History.
- No uptime percentage, availability score, continuous-exposure claim, or inferred open/close interval is calculated.

Regression baseline after implementation: **530/530 tests passing locally on Kali**.

Real text field validation reused `lab-multi.xml`, `lab-multi-after.xml`, and `lab-multi-restored.xml`:
- `192.168.227.128:80/tcp`: `observations=2`, `opportunities=3`. The endpoint was open in the first and third scans and filtered in the middle scan.
- `192.168.227.140:135/tcp`, `:139/tcp`, `:445/tcp`, and `:5357/tcp`: each `observations=3`, `opportunities=3`.

This preserves the evidence-first distinction between “observed open” and “had a valid measurement opportunity”.


### Stage C Exposure History milestone — CLOSED

Exposure History is now a completed Stage C milestone on `main`.

Final validated behavior:
- Stateless history across two or more timestamped Nmap XML scans through `--history`.
- Endpoint identity is normalized host + port + protocol; service/product/version changes do not split endpoint history.
- Only endpoints actually observed `open` at least once are emitted.
- `first_seen` / `last_seen` remain stable integer Unix timestamps in the model/JSON contract.
- Human-readable text uses the more precise labels `first_observed` / `last_observed`.
- `observations` counts scan documents where the endpoint was observed open.
- `opportunities` counts scans where the normalized host was observed up and that port/protocol was explicitly in Nmap scan scope.
- Duplicate endpoint entries inside one scan count once.
- Nmap `started_at` is preferred; `finished_at` is the fallback; missing timestamps fail closed.
- Input order does not determine first/last observation.
- No database, persistence layer, uptime percentage, availability score, inferred duration, or continuous-exposure claim was introduced.
- History complements Diff/Combined Diff rather than replacing their state-change semantics.

Real field validation:
- Text and JSON were both validated against `lab-multi.xml`, `lab-multi-after.xml`, and `lab-multi-restored.xml`.
- Raw XML was cross-checked against the History result.
- `192.168.227.128:80/tcp` was open in the first and third scans and filtered in the middle scan: `observations=2`, `opportunities=3`.
- Four Windows endpoints remained open across all three valid opportunities: `observations=3`, `opportunities=3`.
- JSON preserved the same values and integer timestamps.

Documentation:
- README now exposes the History workflow in the feature list and Quick Start, documents JSON usage, lists `exposure_history.py` in Architecture, and explicitly explains the observational semantics.
- The public `v0.1.0` tag remains immutable; History is post-release development on `main`.

Final regression baseline: **530/530 tests passing**, with GitHub CI green through the History documentation checkpoint.

Next-development rule:
Do not extend History merely to add more metrics. Select the next milestone by identifying a distinct analyst task that NetRecon can remove through evidence-backed correlation, orchestration, interpretation, or workflow without inventing risk or certainty.


### Stage C Finding History milestone — CLOSED

Finding History is now a completed Stage C milestone on `main`.

Validated behavior:
- Stateless history across two or more timestamped Nmap XML scans through `--finding-history`.
- Finding identity reuses the analysis identity: stable finding ID + normalized host + port + protocol.
- `first_seen` / `last_seen` remain integer Unix timestamps in the model/JSON contract; human-readable text uses `first_observed` / `last_observed`.
- `observations` counts supplied scan documents in which the finding was actually emitted, deduplicated per finding identity within each scan.
- `opportunities` counts only scans where the matching host was observed `up` and the finding's required evidence source was actually available.
- NSE-backed opportunities support both port-level and host-level Nmap script placement. This matters for SMB scripts such as `smb-protocols` and `smb2-security-mode`, which real Nmap output may place under host-level scripts even though the resulting finding is scoped to `445/tcp`.
- A scan that covers a service port but did not collect the required NSE script is not a valid opportunity for an NSE-backed finding.
- A valid negative evidence result contributes an opportunity without contributing an observation.
- Source-less fallback findings do not count scans where the matching host is absent or not observed `up` as opportunities.
- Nmap `started_at` is preferred; `finished_at` is the fallback; missing timestamps fail closed.
- Input order does not determine first/last observation.
- No database, persistence claim, duration, continuity inference, vulnerability persistence claim, or risk score was introduced.

Real field validation used:
- `windows-smb.xml`
- `windows-smb-detail.xml`

Both scans target `192.168.227.140` and contain real host-level `smb-protocols` and `smb2-security-mode` evidence. Final installed-CLI text validation reported:
- `service.smb.exposed` on `445/tcp`: `observations=2`, `opportunities=2`.
- `smb.protocol.modern_only` on `445/tcp`: `observations=2`, `opportunities=2`.
- `smb.signing.review` on `445/tcp`: `observations=2`, `opportunities=2`.
- Findings supported only in the first scan remained `observations=1`, `opportunities=1`.

JSON field validation preserved the same five finding-history records, counts, and integer timestamps.

The field test exposed two semantic gaps before closure:
1. Host-level NSE evidence was initially not counted as an opportunity for a port-scoped finding, producing incorrect `0/2` opportunities for the SMB findings. A regression test reproduced the real Nmap structure before the Finding History-specific fallback was added.
2. Findings with `evidence_source=None` could initially count a later down host as an opportunity. A regression test reproduced the case before Finding History was hardened to require the matching host to be observed `up` for every opportunity.

These fixes were deliberately scoped to Finding History; Analysis Diff semantics were not changed as part of this milestone.

Documentation:
- README exposes `--finding-history` in the feature list and Quick Start, documents text/JSON use and evidence-aware opportunity semantics, and lists `finding_history.py` in Architecture.
- The public `v0.1.0` tag remains immutable; Finding History is post-release development on `main`.

Final regression baseline before documentation: **546/546 tests passing**, with GitHub CI green after both field-discovered regression fixes.

Next-development rule:
Do not extend Finding History merely to add percentages or persistence labels. Choose the next milestone by identifying another distinct analyst task that can be removed through explicit evidence, correlation, orchestration, or workflow without inventing risk or certainty.

### Stage C Evidence Gaps milestone — CLOSED

Evidence Gaps is now a completed Stage C milestone on `main`.

Validated behavior:
- `netrecon scan.xml --evidence-gaps` reports planner-supported evidence that is missing from an existing Nmap XML scan without running Nmap.
- `--format json` exposes the same gaps in a stable `evidence_gaps` envelope.
- The existing Evidence Planner remains the single source of truth for what evidence should be collected; Evidence Gaps adds analyst-facing purpose text rather than a second service-detection or collection decision engine.
- Each gap contains normalized host, port, protocol, script ID, and a fixed conservative purpose.
- Existing matching NSE evidence suppresses the gap whether Nmap stored the script under the port or at host level.
- Partial evidence produces only the still-missing sources.
- Unsupported services do not create speculative gaps.
- Multi-host gaps remain bound to the correct host and endpoint.
- `Gaps: 0` means only that no evidence supported by the current planner is missing from the supplied scan. It does not mean the host is safe, fully assessed, or free of vulnerabilities.
- No Nmap execution, automatic collection, vulnerability inference, risk score, or severity claim is introduced by `--evidence-gaps`.

Implementation:
- `evidence_gaps.py` derives `EvidenceGap` records directly from `plan_evidence_requests()`.
- `reporter.py` provides text and JSON renderers.
- `netrecon.py` exposes the operation as a mutually exclusive single-scan CLI mode.
- `evidence_gaps.py` is included in the package module list so installed CLI behavior matches repository tests.
- A no-mock CLI integration test validates XML -> Parser -> Planner -> Evidence Gaps -> Reporter -> CLI using an SMB discovery fixture.

Real field validation:
- `stage-a-discovery.xml` on `192.168.227.138` produced exactly four expected gaps:
  - `445/tcp`: `smb-protocols` — review SMB protocol dialect support.
  - `445/tcp`: `smb2-security-mode` — review SMB signing configuration.
  - `5357/tcp`: `http-title` — review HTTP service identity and exposed content context.
  - `5357/tcp`: `http-methods` — review supported HTTP methods.
- `windows-smb-detail.xml` produced `Gaps: 0`, validating suppression from real host-level SMB NSE evidence.
- JSON field validation on `stage-a-discovery.xml` preserved exactly the same four gaps and all host/port/protocol/script/purpose fields.

A prerequisite planner regression was discovered before CLI exposure: host-level SMB NSE evidence did not originally suppress port-scoped planner requests. The behavior was reproduced by test first, then fixed in the planner so both collection planning and Evidence Gaps share the corrected semantics.

The public `v0.1.0` tag remains immutable; Evidence Gaps is post-release development on `main`.

Next-development rule:
Do not turn Evidence Gaps into speculative vulnerability advice or a duplicate scanner. Future work should build on the separation between discovery, evidence planning, collection, and interpretation, and should only automate another analyst task when the required evidence and semantics are explicit.



### Stage C Evidence Action Plan milestone — CLOSED

Evidence Action Plan is now a completed Stage C milestone on `main`.

Validated behavior:
- `netrecon scan.xml --evidence-actions` converts planner-supported missing evidence into transparent proposed collection actions without running Nmap.
- `--format json` exposes the same actions in a stable `evidence_action_plan` envelope.
- The Evidence Planner remains the source of truth for missing evidence.
- Existing collector grouping and Nmap command construction are reused; Action Plan does not duplicate Nmap syntax or collection decisions.
- Requests sharing host, port, and protocol are grouped into one action while preserving all script IDs and fixed purposes.
- Text output shows the proposed Nmap command for analyst review.
- JSON preserves the exact command as an argv array, avoiding shell-string parsing ambiguity.
- Multi-host actions remain bound to the correct target.
- Existing matching port-level or host-level NSE evidence suppresses redundant actions.
- Unsupported services do not create speculative actions.
- `Actions: 0` means only that no planner-supported collection action is currently required by the supplied scan.
- No subprocess execution, automatic collection, vulnerability inference, risk score, severity claim, or safety claim is introduced by `--evidence-actions`.
- `--evidence-actions` is mutually exclusive with `--collect-evidence` and other CLI modes.

Implementation:
- `evidence_action_plan.py` composes the existing planner, `build_collection_specs()`, `build_nmap_command()`, and Evidence Gaps purpose mapping.
- `reporter.py` provides text and JSON renderers.
- `netrecon.py` exposes `--evidence-actions`.
- `evidence_action_plan.py` is included in package metadata.
- A no-mock CLI integration test validates XML -> Parser -> Planner -> Collection grouping -> Nmap command builder -> Action Plan -> Reporter -> CLI.

Real field validation:
- Installed development CLI was refreshed in `~/netrecon-new-user/NetRecon`.
- `stage-a-discovery.xml` on `192.168.227.138` produced exactly two actions from the four previously validated Evidence Gaps:
  - `445/tcp`: `smb-protocols,smb2-security-mode` -> `nmap -p 445 --script smb-protocols,smb2-security-mode -oX - 192.168.227.138`.
  - `5357/tcp`: `http-title,http-methods` -> `nmap -p 5357 --script http-title,http-methods -oX - 192.168.227.138`.
- JSON field validation preserved exactly the same two actions, endpoints, script IDs, purposes, and commands as argv arrays.
- `windows-smb-detail.xml` produced `Actions: 0`, confirming that real existing host-level SMB NSE evidence does not create redundant actions.

Regression baseline before closure documentation: **568/568 tests passing**, with GitHub CI green before final field-validation documentation.

The public `v0.1.0` tag remains immutable; Evidence Action Plan is post-release development on `main`.

Next-development rule:
Preserve the boundary: Action Plan proposes; `--collect-evidence` executes. Any future Scan Orchestration proof of concept should reuse these existing planner, command, provenance, and reporting layers rather than introducing a second scanner or hiding the exact Nmap actions from the analyst.


### Scan Orchestration POC — Baseline Discovery Execution milestone — CLOSED

The first Scan Orchestration proof of concept is now closed on `main`.

Validated behavior:
- `netrecon --discovery-plan TARGET` builds a transparent, non-executing baseline discovery plan.
- The baseline profile is intentionally conservative: `nmap -sV -oX - TARGET`.
- The target is normalized only for outer whitespace; CIDR input is preserved rather than silently expanded or rewritten.
- `netrecon --discover TARGET` executes exactly the argv stored in the baseline plan with `shell=False`.
- Plan construction, execution, interpretation, and reporting remain separate layers.
- Exit code zero alone is not treated as success: stdout must parse as valid Nmap XML before a verified `Scan` is returned.
- Non-zero Nmap outcomes remain explicit failures and are not parsed as successful scans.
- Timeouts become explicit failed outcomes with return code 124.
- Missing Nmap becomes a controlled failed outcome with return code 127 rather than an uncaught traceback.
- Timeout stdout/stderr are normalized to text even when `TimeoutExpired` supplies bytes.
- Non-positive and non-finite discovery timeouts are rejected before subprocess execution.
- Text and JSON reports preserve the proposed exact command and the parsed Nmap execution provenance.
- No NSE scripts, aggressive scan options, hidden target expansion, vulnerability inference, or automatic evidence collection were added to baseline discovery.

Real field validation:
- Installed development CLI in `~/netrecon-new-user/NetRecon` was refreshed from `main`.
- Preview against the authorized lab target `192.168.227.138` displayed exactly:
  `nmap -sV -oX - 192.168.227.138`.
- Real `--discover` execution succeeded and parsed one up host with four open TCP services:
  - `135/tcp` msrpc
  - `139/tcp` netbios-ssn
  - `445/tcp` microsoft-ds
  - `5357/tcp` http
- The text report preserved both the NetRecon-planned command and Nmap's own reported arguments.
- A separate JSON field run returned `report_type: discovery_execution`, `status: success`, `returncode: 0`, `timed_out: false`, the exact command argv, and the same host/service inventory.

Final regression baseline after execution hardening: **600/600 tests passing**. GitHub CI was independently verified green on Python 3.10, 3.11, 3.12, 3.13, and 3.14 for commit `5119c655c867584978ecf90d4760b59d01efe7a9`.

The public `v0.1.0` tag remains immutable; Scan Orchestration development is post-release work on `main`.

Next-development rule:
Preserve the transparent chain `Target -> Discovery Plan -> exact Nmap argv -> Executor -> raw outcome -> validation/parsing -> verified Scan`. The next orchestration step should build on the verified discovery result and existing Evidence Planner / Evidence Gaps / Evidence Action Plan layers rather than introducing a second scanner, hiding Nmap actions, or automatically escalating scan aggressiveness.


## Investigation Orchestration POC — Text field validation

Validated on the authorized Kali lab target `192.168.227.138` using the installed-package checkout:

```bash
netrecon --investigate 192.168.227.138
```

Observed result:
- Investigation status: `ready`.
- 4 planner-supported evidence gaps were identified.
- 2 transparent evidence collection actions were proposed.
- SMB action: port 445 with `smb-protocols,smb2-security-mode`.
- HTTP action: port 5357 with `http-title,http-methods`.
- Exact proposed Nmap argv was visible to the analyst.
- Evidence actions were not executed automatically.

This validates the first end-to-end analyst-review path:

```text
Target -> Baseline Discovery -> Verified Scan -> Evidence Gaps -> Evidence Action Plan -> Analyst Review
```

The orchestration remains deliberately bounded: discovery executes, while follow-up evidence collection is proposed only.


## Investigation Orchestration POC — CLOSED

JSON field parity was validated on the authorized Kali lab target `192.168.227.138`:

```bash
netrecon --investigate 192.168.227.138 --format json
```

Observed machine-readable result:
- `report_type: investigation_snapshot`
- `status: ready`
- summary: 4 evidence gaps and 2 proposed actions
- the four gaps matched the text report exactly:
  - 445/tcp: `smb-protocols`
  - 445/tcp: `smb2-security-mode`
  - 5357/tcp: `http-title`
  - 5357/tcp: `http-methods`
- the two proposed actions matched the text report exactly.
- each action preserved its exact Nmap command as an argv array.
- no evidence action was executed automatically.

The first Investigation Orchestration POC is therefore closed with both human-readable and machine-readable field validation.

Closed workflow:

```text
Target
  -> Baseline Discovery (executes)
  -> Verified Scan
  -> Evidence Gaps
  -> Evidence Action Plan
  -> Analyst Review (stops here)
```

Preserved architectural boundary:
> Discovery executes; follow-up evidence actions are proposed, transparent, and remain under analyst control.


## Investigation State / Known–Unknown Model — CLOSED

NetRecon now exposes an evidence-traceable investigation state as part of `--investigate`.

- `known` contains only observed Discovery facts for open endpoints: state, normalized service, and product/version when actually observed.
- `unknown` contains only planner-supported `EvidenceGap` objects; NetRecon does not invent security conclusions from service identity alone.
- Unsupported endpoints remain visible as known Discovery state with no fabricated unknowns.
- `InvestigationSnapshot` composes state from the same verified Scan used by Evidence Gaps and Evidence Actions.
- Text and JSON reporters expose the same state. JSON includes `summary.investigation_states` and structured `states[]`.
- The execution boundary is unchanged: `--investigate` executes baseline Discovery only. Evidence Actions remain transparent proposals and are not executed automatically.
- Regression baseline: 616/616 tests passing.
- Field validation on `192.168.227.138` passed in both text and JSON:
  - 4 endpoint states: 135/tcp, 139/tcp, 445/tcp, 5357/tcp
  - 4 evidence gaps
  - 2 proposed evidence actions
  - 135/139 expose observed facts only
  - 445 exposes SMB dialect/signing unknowns
  - 5357 exposes HTTP title/method unknowns
  - exact proposed Nmap argv remains visible and unexecuted.

This milestone establishes the explicit state question: **what is known, what is unknown, and what evidence would reduce the unknowns?**


## Investigation Continuation / Evidence Collection Loop — CLOSED

NetRecon now supports an explicit one-pass investigation continuation workflow:

```text
Discover
  -> Known / Unknown
  -> Evidence Gaps
  -> Proposed Actions
  -> Collect approved evidence
  -> Re-evaluate
  -> Updated Known / Unknown
```

### CLI boundary

- `--investigate TARGET` remains preview-only. It runs baseline Discovery, builds Investigation State / Evidence Gaps / Evidence Actions, and stops without executing evidence actions.
- `--investigate-collect TARGET` is the explicit execution boundary. It runs baseline Discovery, executes exactly the displayed planner-supported evidence action argv once, preserves collection outcomes, and re-evaluates the investigation.
- Newly proposed actions after re-evaluation are displayed but are not recursively executed.
- A blocked/failed Discovery never executes evidence actions.
- `--evidence-timeout` applies consistently to Discovery and approved evidence collection.

### Evidence semantics

Collection execution success is intentionally separate from requested-evidence completeness:

- `Collection Status: success` means the collection command returned parseable Nmap XML.
- `Requested Evidence: observed` means the requested evidence is no longer represented by a planner-supported gap after re-evaluation.
- `Requested Evidence: incomplete` means collection succeeded technically but one or more requested evidence gaps remain.
- Failed or timed-out collection does not reduce Unknowns.
- Exit code 0 alone is never treated as proof that requested evidence was obtained.

The exact executed argv, return code, failure information, requested-evidence state, and missing evidence are preserved in continuation reporting.

### Reporting

Text and JSON continuation reports are supported.

JSON uses `report_type: investigation_continuation` and includes:

- `collection_outcomes`
  - exact `argv`
  - `collection_status`
  - `requested_evidence`
  - `missing_evidence`
  - `returncode`
  - `failure`
- `updated_investigation`
  - the re-evaluated `investigation_snapshot`

### Field validation

Authorized target: `192.168.227.138`.

Preview remained unchanged:

- 4 evidence gaps
- 2 proposed actions
- no evidence actions executed

Explicit continuation executed exactly two proposed actions:

- SMB 445: `smb-protocols,smb2-security-mode`
- HTTP 5357: `http-title,http-methods`

Observed result:

- SMB collection succeeded and requested evidence was observed; both SMB Unknowns disappeared.
- HTTP collection succeeded technically, but `http-title` and `http-methods` evidence was not observed; both Unknowns remained and one HTTP action remained proposed.
- This field result validated the evidence-first distinction between command success and evidence completeness.
- Text and JSON output were both field-validated.
- Installed entry-point help exposes both `--investigate` and `--investigate-collect`.

### Verification baseline

- Full local suite: **632/632 passing**
- GitHub Actions: Python 3.10–3.14 green before final field validation.
- No recursive Auto-Run was introduced.
- No second planner or decision engine was introduced.
- Existing evidence correlation, gap planning, action planning, and investigation-state engines remain the source of truth.

Milestone status: **CLOSED**.

## Semantic Investigation Core — CLOSED

NetRecon now separates raw collection-mechanism gaps from the semantic analyst requirements those collectors are intended to satisfy.

Closed bounded workflow:

```text
Discover
  -> Plan semantic evidence needs
  -> Collect primary evidence once
  -> Re-evaluate
  -> Guard repeated actions
  -> Select one supported semantic alternative when available
  -> Collect alternative once
  -> Verify exact observed evidence
  -> Final semantic decision
  -> STOP
```

### Semantic evidence model

- Script-specific `EvidenceGap` objects remain the provenance truth for what an Nmap collector did or did not return.
- `EvidenceRequirement` represents the analyst knowledge need independently of its collection mechanism.
- `EvidenceRequirementState` binds that need to an exact host/port/protocol endpoint.
- Requirement state is deduplicated by endpoint plus requirement identity.
- Primary semantic progress is tracked separately from verified alternative satisfaction.
- Alternative evidence can satisfy a semantic requirement only on the exact endpoint and only when the configured alternative script is actually observed with non-empty output.
- A raw script gap may remain visible even when a verified alternative has satisfied the corresponding semantic requirement.
- Final investigation completion is therefore allowed when all semantic requirements are satisfied while raw gaps remain preserved as collection provenance.

### Bounded continuation and safety

- Exact repeated primary commands are blocked from automatic re-execution.
- Stall diagnosis distinguishes repeated-action exhaustion, unsupported actions, and no progress.
- The current bounded alternative catalog includes `http-headers` only for the `http_identity_context` requirement originally associated with `http-title`.
- `http-headers` is not treated as equivalent to `http-methods`; `http_supported_methods` has no fabricated alternative.
- No speculative SMB, SSH, or TLS alternatives were added merely to make the catalog look generic.
- At most one supported alternative collection round is executed.
- There is no recursive Auto-Run or unlimited Nmap chaining.

### Semantic provenance reporting

Continuation reporting now distinguishes:
- semantic requirements resolved by primary collection;
- requirements satisfied by verified alternative evidence;
- requirements still unresolved.

When both continuation and final decisions are available, text reporting includes:

```text
Semantic Requirement Progress
-----------------------------
Resolved by Primary: <count>
Satisfied by Alternative: <count>
Remaining: <count>
```

JSON exposes the same information in `semantic_requirement_progress`.

### Regression baseline

- Full suite: **674/674 tests passing**.
- GitHub Actions green after the semantic progress summary regression test.
- Production behavior and reporter contracts are covered separately, including semantic completion with preserved raw-gap provenance and partial alternative satisfaction.

### Real field validation

Authorized lab target: `192.168.227.138`.

Primary collection:
- SMB 445 with `smb-protocols,smb2-security-mode`: collection succeeded and requested evidence was observed.
- HTTP 5357 with `http-title,http-methods`: collection succeeded technically but both requested script results remained absent.

Continuation result:
- `Status: stalled`
- `Stall Reason: repeated_actions_exhausted`
- 2 raw gaps resolved.
- 2 semantic requirements resolved by primary collection:
  - `smb_protocol_support`
  - `smb_signing_configuration`
- 2 HTTP raw gaps remained.
- repeated primary HTTP action was blocked.
- one supported semantic alternative, `http-headers`, was selected.

Alternative round:
- `http-headers` executed once.
- verification result: `incomplete`.
- no semantic requirement was falsely marked satisfied.

Final semantic progress:
- `Resolved by Primary: 2`
- `Satisfied by Alternative: 0`
- `Remaining: 2`

Final decision:
- `Status: stalled`
- `Reason: alternative_evidence_incomplete`
- remaining endpoint-bound requirements:
  - `192.168.227.138:5357/tcp http_identity_context`
  - `192.168.227.138:5357/tcp http_supported_methods`
- further supported actions: 0.

The field result confirms the intended evidence-first boundary: a successful Nmap process is not treated as successful investigation evidence, unsupported semantic equivalence is not invented, and the investigation stops explicitly when the bounded evidence strategy is exhausted.

Milestone status: **CLOSED**.

Next-development rule:
Build above this semantic provenance layer rather than adding more collectors by default. New alternative collectors should be introduced only when their evidence semantics are defensible and verifiable. Preserve the bounded STOP behavior and the distinction between Nmap collection provenance and NetRecon investigation knowledge.



## Analyst Attention — Investigation Integration FIELD-VALIDATED

NetRecon now projects evidence-backed Findings into a bounded analyst-review layer after investigation evidence has been collected and merged.

Validated workflow:

```text
Nmap Discovery
  -> Evidence Gaps / Semantic Requirements
  -> Targeted Evidence Collection
  -> Merge and Re-evaluate
  -> Evidence-backed Findings
  -> Analyst Attention
```

### Architectural boundary

Analyst Attention is not a second findings engine and does not invent vulnerabilities, risk scores, severity rankings, or unsupported conclusions. It is a projection over the existing evidence-backed Findings engine.

Initial review-worthy Finding categories:
- `configuration`
- `exposure`
- `transport`
- `visibility`

Informational `context` and `protocol` findings remain outside Attention by design. Attention preserves Finding order and evidence provenance rather than introducing a new severity ranking.

`--attention` provides a standalone projection from an existing Nmap XML. `--investigate-collect` now builds Attention from the final merged investigation snapshot: the alternative-round snapshot when one exists, otherwise the primary re-evaluated snapshot.

Text continuation output includes a distinct `Analyst Attention` section. JSON includes a structured `analyst_attention` envelope.

### Regression baseline

- Full suite: **682/682 tests passing**.
- GitHub Actions green.
- Regression coverage proves that merged NSE evidence can create a new Attention item with NSE provenance.
- CLI coverage proves Attention is built from the final alternative snapshot rather than baseline or intermediate state.
- Reporter coverage preserves Attention provenance in both Text and JSON.

### Real field validation

Authorized Kali lab target: `192.168.227.138`.

Command:

```bash
netrecon --investigate-collect 192.168.227.138
```

The bounded semantic investigation behaved as previously validated:
- SMB primary evidence was observed.
- HTTP primary evidence remained incomplete.
- the one supported `http-headers` alternative was attempted once and remained incomplete.
- final status: `stalled`.
- reason: `alternative_evidence_incomplete`.
- further supported actions: 0.

The final merged evidence produced **4 Analyst Attention items**.

Three were derived directly from Discovery service evidence:
- Windows RPC endpoint mapper exposed — `service:detection`
- NetBIOS session service exposed — `service:detection`
- SMB service exposed — `service:detection`

A fourth item was created only after targeted NSE evidence collection:
- **SMB signing configuration requires review**
- endpoint: `192.168.227.138:445/tcp`
- observed evidence: `3.1.1: Message signing enabled but not required`
- provenance: `nse:smb2-security-mode`

This is the first real field proof that targeted evidence selected during a NetRecon investigation can enrich the merged investigation state, produce a new evidence-backed Finding, and surface a traceable analyst-review item that was not available from baseline service discovery alone.

### Product milestone

The project vision is now demonstrated end-to-end in the authorized lab:

> **Nmap discovers the network. NetRecon decides what evidence to collect, turns it into intelligence, and shows the analyst what deserves attention.**

Milestone status: **FIELD-VALIDATED**.

### Next development direction

Build above the validated Attention layer rather than expanding collectors by default. The next work should focus on making analyst attention more useful without losing evidence provenance or introducing arbitrary risk scoring. Candidate work should be evaluated against one question:

> What does NetRecon do with collected evidence that an analyst should not have to correlate manually?

Preserve:
- evidence-first provenance;
- semantic requirement separation;
- bounded collection and explicit STOP;
- no fabricated vulnerability conclusions;
- no arbitrary risk score;
- no automatic severity ranking of Attention items.


## Attention Correlation — FIELD-VALIDATED

NetRecon now has a bounded correlation layer above Analyst Attention. It groups only explicitly supported relationships between existing evidence-backed Attention items; it does not create new findings, assign risk scores, rank severity, or infer vulnerability.

Validated flow:

```text
Nmap Discovery
  -> Semantic Evidence Planning
  -> Targeted Evidence Collection
  -> Merged Investigation Snapshot
  -> Evidence-backed Findings
  -> Analyst Attention
  -> Explicit Attention Correlation
  -> Correlated Review
```

### First bounded correlation rule

The first supported relationship is intentionally narrow:

- `service.smb.exposed`
- `smb.signing.review`
- both must belong to the same host.

NetBIOS is not included merely because it is commonly related to SMB. No generic same-host correlation exists. New relationships must be explicit and evidence-defensible.

The resulting correlation is:

- correlation ID: `smb.exposure_and_signing_review`
- title: `SMB exposure and signing configuration require joint review`
- source findings are preserved;
- evidence provenance is preserved;
- review guidance asks the analyst to assess the observations together without declaring a vulnerability.

### Regression baseline

- Full suite: **686/686 tests passing**.
- GitHub Actions green.
- Unit coverage verifies same-host SMB exposure/signing correlation and rejects cross-host correlation.
- Reporter coverage preserves source Finding IDs and evidence sources in standalone correlation output and in integrated investigation Text/JSON.
- CLI coverage verifies the chain from final investigation Attention to correlation and reporting.

### Field-discovered contract defect

The first authorized field run produced four valid Attention items but `Correlated Review / Groups: 0`.

The field result exposed a fixture/production identity mismatch:
- production SMB exposure Finding ID: `service.smb.exposed`
- the initial correlation implementation and synthetic unit fixture incorrectly used `smb.service.exposed`.

The production correlation rule and regression fixtures were corrected to use the existing canonical Finding ID. No Finding ID was renamed and no evidence logic was weakened to make the test pass.

This is an important testing lesson for future correlation work: synthetic Attention fixtures can drift from production Finding contracts. Prefer regression paths derived from canonical production Findings when practical.

### Real field validation

Authorized Kali lab target: `192.168.227.138`.

After the canonical-ID correction, the repeated bounded investigation produced the same four Attention items, including:

- `service.smb.exposed` from `service:detection`
- `smb.signing.review` from `nse:smb2-security-mode`

The integrated report then produced:

```text
Correlated Review
-----------------
Groups: 1

SMB exposure and signing configuration require joint review
  Host: 192.168.227.138
  Findings: service.smb.exposed, smb.signing.review
  Evidence Sources: service:detection, nse:smb2-security-mode
```

The HTTP branch remained independently stalled with `alternative_evidence_incomplete`, demonstrating that correlation does not hide unresolved evidence requirements or alter bounded STOP behavior.

This validates the complete product path:

> **Discovery -> Evidence Need -> Targeted Collection -> Finding -> Analyst Attention -> Correlated Review**

Milestone status: **FIELD-VALIDATED**.

### Next-development rule

Do not expand correlation by accumulating convenient same-host rules. The next intelligence layer should solve a clear analyst problem while preserving canonical Finding identities and provenance. Correlation should remain an explicit semantic relationship over existing Attention items, not become an implicit scoring or vulnerability engine.


## Investigation Synthesis — FIELD-VALIDATED

NetRecon now has a factual synthesis layer above the final investigation decision, Analyst Attention, and explicit Attention Correlation. Synthesis is a consumer of existing investigation truth; it does not collect evidence, create Findings, rank risk, or alter investigation decisions.

Validated flow:

```text
Nmap Discovery
  -> Semantic Evidence Planning
  -> Targeted Evidence Collection
  -> Re-evaluation
  -> Final Investigation Decision
  -> Evidence-backed Findings
  -> Analyst Attention
  -> Explicit Attention Correlation
  -> Investigation Synthesis
```

### Current synthesis contract

The first bounded synthesis reports only:
- final investigation status;
- final decision reason;
- number of Analyst Attention items;
- number of Correlated Review groups;
- remaining semantic evidence requirements.

Text and JSON have dedicated deterministic reporting contracts. CLI integration currently builds Synthesis only when an explicit `FinalInvestigationDecision` exists; it does not fabricate a terminal decision for investigation paths that do not yet produce one.

### Regression and packaging

The new `investigation_synthesis.py` module is included in the installed package. A field-independent regression covers the factual model, Text/JSON reporting, and the terminal CLI chain:

```text
Final Decision -> Attention -> Correlation -> Synthesis -> CLI output
```

GitHub Actions was green before field validation.

### Real field validation

Authorized Kali lab target: `192.168.227.138`.

Command:

```bash
netrecon --investigate-collect 192.168.227.138
```

Observed terminal state:
- final status: `stalled`;
- reason: `alternative_evidence_incomplete`;
- Analyst Attention items: 4;
- Correlated Review groups: 1;
- remaining semantic requirements: 2.

The remaining requirements were:
- `http_identity_context` on `192.168.227.138:5357/tcp`;
- `http_supported_methods` on `192.168.227.138:5357/tcp`.

The integrated terminal report ended with:

```text
Investigation Synthesis
-----------------------
Status: stalled
Reason: alternative_evidence_incomplete
Attention Items: 4
Correlated Review Groups: 1
Remaining Requirements: 2
Requirement: 192.168.227.138:5357/tcp  http_identity_context — review HTTP service identity and exposed content context
Requirement: 192.168.227.138:5357/tcp  http_supported_methods — review supported HTTP methods
```

The synthesis matched the underlying investigation layers exactly. It preserved the unresolved HTTP knowledge needs rather than converting missing evidence into a Finding, and it preserved the SMB Attention/Correlation results without allowing them to hide unresolved requirements.

This is the first field proof that NetRecon can close a bounded investigation run with one coherent factual view of:
- what state the investigation reached;
- why it stopped;
- what evidence-backed observations deserve analyst review;
- what related evidence should be reviewed together;
- what remains unknown.

Milestone status: **FIELD-VALIDATED**.

### Next development direction

Investigation Synthesis is now a validated layer. Before expanding its prose or adding interpretation, preserve its role as a factual projection over existing truth.

The next major vision layer is **Investigation Memory / History**: enable NetRecon to compare investigation knowledge over time while preserving endpoint identity, evidence provenance, and the distinction between observed change and analyst interpretation.


## Investigation Memory / History V1 — FIELD-VALIDATED

NetRecon now persists and compares completed factual investigation states across runs. This layer remembers **investigation knowledge state** rather than duplicating the existing endpoint Exposure History or evidence-backed Finding History.

Validated flow:

```text
Investigation Synthesis
  -> Opt-in append-only History
  -> Previous same-target Synthesis
  -> Factual Investigation Memory
  -> Current-vs-previous change report
```

### V1 memory contract

`InvestigationMemory` compares two `InvestigationSynthesis` states and reports only factual change:

- previous/current final status and whether it changed;
- previous/current final reason and whether it changed;
- Analyst Attention item count delta;
- Correlated Review group count delta;
- added semantic requirements;
- resolved semantic requirements.

It does not label a change as improvement/deterioration, safer/riskier, or assign severity/risk.

Requirement identity remains endpoint- and semantics-aware:
`(normalized host, port, normalized protocol, requirement_id)`.

### Persistence contract

History is explicitly opt-in:

```bash
netrecon --investigate-collect TARGET --investigation-history FILE
```

The store is append-only JSONL. Each completed record contains:
- `schema_version: 1`;
- observation timestamp;
- target;
- complete factual `InvestigationSynthesis`.

The current parser accepts only schema version 1. Unsupported/missing versions fail closed rather than being guessed. History read/write errors return a clear CLI error and exit code 2. A failed history load is not silently skipped and no new record is appended to an untrusted history stream.

`--investigation-history` is valid only with `--investigate-collect`; misuse is rejected by the CLI.

Previous-state selection is target-scoped and timestamp-based. A newer record for another target is not used as comparison context.

### Regression baseline

- Full suite after the V1 CLI-contract regression: **699/699 tests passing**.
- GitHub Actions green.
- Coverage includes model comparison, Text/JSON reporting, JSON round-trip tuple preservation, append/load ordering, same-target previous-state selection, persistence flow, visible CLI Memory reporting, fail-closed invalid-history behavior, and CLI modifier validation.

### Real field validation

Authorized Kali lab target: `192.168.227.138`.

A clean History baseline was created with:

```bash
rm -f investigation-history.jsonl
netrecon --investigate-collect 192.168.227.138 --investigation-history investigation-history.jsonl
```

The first terminal investigation produced the expected Synthesis and no Memory section because no previous same-target investigation existed. Its factual state was persisted as the baseline.

A second investigation used the same target and History file:

```bash
netrecon --investigate-collect 192.168.227.138 --investigation-history investigation-history.jsonl
```

The second run recalled the previous same-target Synthesis and produced:

```text
Investigation Memory
--------------------
Status: stalled -> stalled
Status Changed: no
Reason: alternative_evidence_incomplete -> alternative_evidence_incomplete
Reason Changed: no
Attention Item Change: +0
Correlated Review Group Change: +0
Added Requirements: 0
Resolved Requirements: 0
```

This is a useful stable-state validation: NetRecon did not invent change when the underlying investigation state remained the same.

The field run therefore demonstrates:

> **Investigate -> Persist -> Re-investigate -> Recall same target -> Compare -> Report factual change**

Milestone status: **FIELD-VALIDATED**.

### Architectural boundary

Investigation Memory does not replace:
- Exposure History, which tracks observed open endpoints over scans;
- Finding History, which tracks repeated evidence-backed Findings.

Memory V1 tracks the higher-level investigation knowledge state represented by Synthesis.

Only runs that produce a real terminal `InvestigationSynthesis` are currently persisted. Investigation paths without a `FinalInvestigationDecision` remain outside this V1 contract rather than receiving an invented terminal state.

### Next major vision layer

With factual single-run Synthesis and cross-run Memory now field-validated, the next major layer is **Adaptive Investigation Planning**.

The planning question is no longer only:

> What evidence is missing now?

It becomes:

> Given what this investigation already knows, what it tried before, what remains unresolved, and what changed over time, what is the next evidence action that is actually justified?

Preserve the existing product constraints: evidence-first reasoning, bounded collection, explicit semantic alternatives, provenance, repeat guards, and explicit STOP. Adaptive planning must not become uncontrolled scanning or speculative vulnerability hunting.


## Adaptive Investigation Planning V1 — FIELD-VALIDATED (REPORT-ONLY)

NetRecon now projects the existing continuation truth into one explicit bounded next-step decision:

```text
Continuation Decision
  -> Adaptive Investigation Plan
  -> continue | alternative | stop
```

The Adaptive layer does not invent Nmap scripts, risk scores, severity, or unsupported collection. It can continue only when an existing planner-supported `EvidenceAction` is available.

V1 decisions:
- `continue` — a new supported primary evidence action exists;
- `alternative` — primary collection is exhausted and an explicit supported semantic alternative exists;
- `stop` — the investigation is complete or no supported next step remains.

The current CLI integration is deliberately opt-in and report-only:

```bash
netrecon --investigate-collect TARGET --adaptive-plan
```

Without `--adaptive-plan`, legacy Text and JSON output contracts remain unchanged. With the flag, NetRecon renders the factual Adaptive decision, reason, and exact supported actions. The existing proven orchestration path still controls execution; Adaptive V1 does not yet execute actions itself.

### Regression baseline

- Full suite: **702/702 tests passing**.
- GitHub Actions green.
- Coverage includes the adaptive decision model, Text/JSON reporting, opt-in CLI reporting, legacy output compatibility, and proof that enabling the Adaptive report does not replace the existing alternative-execution path.

### Real field validation

Authorized Kali lab target: `192.168.227.138`.

Command:

```bash
netrecon --investigate-collect 192.168.227.138 --adaptive-plan
```

The primary HTTP evidence action remained incomplete, so Continuation reported:
- status `stalled`;
- stall reason `repeated_actions_exhausted`;
- zero safe next primary actions;
- one explicit supported alternative:
  `nmap -p 5357 --script http-headers -oX - 192.168.227.138`.

Adaptive Planning independently projected that state as:

```text
Adaptive Investigation Plan
---------------------------
Decision: alternative
Reason: supported_alternative_actions_available
Actions: 1
Action: nmap -p 5357 --script http-headers -oX - 192.168.227.138
```

The existing orchestration path executed exactly that same `http-headers` action. Verification remained `incomplete`, and the final investigation stopped with `alternative_evidence_incomplete`, zero further supported actions, and the two unresolved HTTP semantic requirements preserved.

This field run proves the key V1 invariant:

> **Adaptive Planning recommends exactly the bounded action already justified by investigation state, and does not invent another step when evidence remains incomplete.**

Milestone status: **FIELD-VALIDATED (REPORT-ONLY)**.

### Next architectural decision

Do not automatically promote Adaptive Planning into the execution controller. The report-only phase first establishes agreement between adaptive reasoning and the existing proven orchestration path.

The next development step is to define the controller boundary carefully: determine whether Adaptive should become the single authority that selects among already-supported actions, while evidence execution remains a separate bounded mechanism. Avoid creating a circular dependency between `adaptive_investigation.py` and `investigation_orchestration.py`.


## Adaptive Controller Boundary — ALTERNATIVE PATH FIELD-VALIDATED

Adaptive Planning has now moved beyond report-only operation for the bounded alternative-evidence path.

The execution boundary is:

```text
Continuation Decision
  -> Adaptive Plan
  -> select_adaptive_actions()
  -> Existing Alternative Evidence Executor
  -> Verification
  -> Final Investigation Decision
```

Adaptive still does not construct Nmap commands or execute collection directly. It may select only the exact `EvidenceAction` objects already justified by the existing continuation/planning layers. The existing executor remains responsible for collection and the existing alternative verifier remains responsible for deciding whether requested evidence was actually observed.

A controller guard is regression-tested: an Adaptive `stop` decision yields no executable actions and blocks the alternative executor even if an inconsistent upstream decision object contains alternative actions.

### Field validation

Authorized Kali lab target: `192.168.227.138`.

Command:

```bash
netrecon --investigate-collect 192.168.227.138 --adaptive-plan
```

Observed agreement across the control path:

```text
Continuation:
Alternative: nmap -p 5357 --script http-headers -oX - 192.168.227.138

Adaptive:
Decision: alternative
Reason: supported_alternative_actions_available
Action: nmap -p 5357 --script http-headers -oX - 192.168.227.138

Alternative Evidence Round:
Command: nmap -p 5357 --script http-headers -oX - 192.168.227.138
Verification: incomplete
```

The final decision remained:

```text
Status: stalled
Reason: alternative_evidence_incomplete
Further Supported Actions: 0
```

This proves in the field that the alternative action executed only after passing through the Adaptive Controller, while execution/verification remained bounded and unchanged. Incomplete alternative evidence did not trigger invented follow-up scanning.

Milestone status: **ALTERNATIVE CONTROLLER PATH FIELD-VALIDATED**.

### Remaining controller boundary

Do not generalize this immediately into an autonomous investigation loop. Primary evidence collection still follows the established orchestration path. The next controller work should determine how a `continue` decision can authorize an already-supported next primary action without creating repeated-action loops, bypassing the repeat guard, or duplicating continuation logic.


## Adaptive Controller Boundary — CONTINUE PATH CODE-VALIDATED

The Adaptive Controller now supports one bounded `continue` round without becoming an autonomous investigation loop.

Execution boundary:

```text
Primary Evidence Round
  -> Continuation Assessment
  -> Adaptive Plan
  -> select_adaptive_actions()
  -> One Existing Selected-Evidence Execution Round
  -> Continuation Reassessment
  -> Stop / report the newly supported decision
```

Safety constraints:

- `continue` may execute only exact `EvidenceAction` objects already exposed through `continuation.next_actions`.
- Repeat-guard filtering remains authoritative before controller selection.
- Previously attempted commands are excluded from `next_actions`.
- The CLI permits at most one additional adaptive Continue round; there is no `while` loop or recursive continuation.
- A second `continue` decision is reported but does not trigger another Continue execution round.
- Existing evidence execution remains in `execute_selected_evidence_actions()`; the Adaptive Controller does not construct Nmap commands.
- The previously validated Alternative Controller path remains bounded and unchanged in responsibility.

Validation:

- GitHub CI baseline after the Continue guard: **707/707 tests passing**.
- Regression coverage verifies that the controller selects only repeat-guard-safe next actions.
- CLI coverage verifies one bounded Continue round and explicitly verifies that a further Continue decision cannot cause a third evidence round.

### Field validation note — 192.168.227.138

The authorized field run:

```text
netrecon --investigate-collect 192.168.227.138 --adaptive-plan
```

did **not** naturally produce a `continue` decision. The Primary round resolved the two SMB requirements, while the HTTP evidence request on 5357 remained incomplete. Its repeated primary action was blocked, so the investigation correctly followed the already-supported bounded Alternative path:

```text
Continuation: stalled
Stall Reason: repeated_actions_exhausted
Resolved Gaps: 2
Next Actions: 0
Repeat-Blocked Actions: 1
Alternative Actions: 1

Adaptive:
Decision: alternative
Action: nmap -p 5357 --script http-headers -oX - 192.168.227.138

Final:
Status: stalled
Reason: alternative_evidence_incomplete
Further Supported Actions: 0
```

This field run is therefore a regression/safety validation of the controller integration, **not** a claim that the Continue branch itself was field-exercised.

Architectural finding: the current Primary evidence round executes all planner-supported actions already visible in the initial snapshot. A natural `continue` field case therefore requires newly collected evidence to reveal a new planner-supported evidence gap/action that was not known before the Primary round. Do not manufacture a production rule merely to force this scenario.

Milestone: **CONTINUE CONTROLLER PATH CODE-VALIDATED; NATURAL FIELD CASE PENDING.**


## Finding-derived Approval / Verification / Lifecycle — FIELD-VALIDATED

NetRecon now carries a finding-derived semantic requirement through an explicit human authorization boundary, bounded evidence collection, semantic verification, and durable lifecycle state.

Field-validated path:

```text
Finding
  -> Finding-derived semantic requirement
  -> Explicit human approval
  -> Authorized EvidenceAction
  -> Nmap collection
  -> Semantic verification
  -> Finding requirement lifecycle
```

Authorized Kali lab target: `192.168.227.138`.

The observed SMB finding `smb.signing.review`, sourced from `nse:smb2-security-mode`, derives the semantic requirement `smb_access_control_context`. Its supported collection strategy is `smb-enum-shares`, classified as intrusive and therefore blocked until explicit approval.

Without approval, the real field run displayed `Pending Approval` and did not execute `smb-enum-shares`.

With:

```bash
netrecon --investigate-collect 192.168.227.138 --adaptive-plan --approve-requirement smb_access_control_context
```

NetRecon executed exactly one bounded dynamic collection:

```text
Command: nmap -p 445 --script smb-enum-shares -oX - 192.168.227.138
Collection Status: success
Return Code: 0
Requirement: smb_access_control_context — unsatisfied
Outcome: requested evidence was not observed
Next Step: no automatic retry or unsupported alternative
```

This validates an important semantic invariant: process success (`Return Code: 0`) is not treated as proof that the requested evidence was observed.

### Lifecycle bugs exposed by field testing

The first approved field run exposed that a later unrelated HTTP alternative round could erase the prior SMB verification. The final Snapshot incorrectly reverted the requirement to `pending_approval`.

The lifecycle implementation was corrected so finding verifications are merged across evidence rounds by endpoint-scoped requirement identity:

```text
(requirement_id, host, port, protocol)
```

A current verification replaces only the same exact identity; unrelated prior verification history survives.

A second field run then exposed a separate authorization-propagation bug: lifecycle correctly remained `attempted_unsatisfied`, but the final Snapshot still displayed `Pending Approval` because the CLI approval set was not propagated into the later Alternative evidence round.

Alternative-round execution now receives the same explicit approval set used by the investigation. This changes re-evaluation state only; it does not re-execute the finding-derived action.

### Final field result

The final approved field run produced:

```text
Finding Requirement Lifecycle
Requirement State: 192.168.227.138:445/tcp  smb_access_control_context — attempted_unsatisfied
  Authorization: explicitly_approved
```

and:

- no `Pending Approval` for that attempted requirement;
- exactly one `smb-enum-shares` execution;
- semantic verification remained `unsatisfied`;
- no automatic SMB retry;
- no invented SMB alternative;
- the later unrelated HTTP alternative round did not erase SMB lifecycle or approval state.

The HTTP 5357 investigation independently remained bounded and stalled with `alternative_evidence_incomplete`; this does not change the terminal SMB lifecycle result.

Milestone status: **APPROVAL + SEMANTIC VERIFICATION + MULTI-ROUND LIFECYCLE FIELD-VALIDATED**.

### Architectural invariant

Planner truth and execution history remain separate:

- the finding planner answers what current evidence justifies;
- authorization answers whether the proposed boundary may be crossed;
- the executor performs only selected approved actions;
- semantic verification answers whether requested evidence was actually observed;
- lifecycle history remembers prior outcomes across unrelated rounds;
- re-planning must not interpret absence of evidence as permission to retry an already-attempted requirement.

Do not collapse `attempted_unsatisfied` back into `pending_approval`, and do not regenerate an automatic action for an exact requirement identity whose terminal verification is already known.


## Finding Requirement Lifecycle → Decision Semantics

The finding-requirement lifecycle is now part of investigation control flow, not merely report metadata.

Both continuation and final-decision layers understand terminal and authorization states. The validated semantics are:

| Lifecycle state | Continuation meaning | Final-decision meaning |
| --- | --- | --- |
| `pending_approval` | stalled: `explicit_approval_required` | stalled: `explicit_approval_required` |
| `authorized_pending` | eligible to progress through the authorized dynamic-action pipeline | collection/execution path remains responsible for producing a terminal verification |
| `satisfied` | does not block completion when primary evidence is complete | complete is allowed when no primary gaps remain |
| `attempted_unsatisfied` | stalled: `finding_requirement_unsatisfied` | stalled: `finding_requirement_unsatisfied` |

Important invariant: `all_gaps_resolved` refers to more than an empty primary `EvidenceGap` set. A finding-derived semantic requirement that is still waiting for human approval or that was attempted without observing the requested evidence prevents a false successful completion.

Conversely, a terminal `satisfied` finding requirement must not manufacture a stall or hide a genuine primary evidence gap.

The implementation retains the older plan-derived approval check for compatibility, while `FindingRequirementState` is now a direct semantic input to continuation and final-decision reasoning.

Regression sequence:
- `1f476c4` / `d300a7b`: pending-approval lifecycle drives continuation.
- `9a72912` / `9019bac`: attempted-unsatisfied lifecycle prevents false final completion.
- `39b372b` / `cfbc057`: pending-approval lifecycle prevents false final completion.
- `9e9db43`: satisfied lifecycle explicitly permits final completion when no primary gaps remain.

Milestone status: **FINDING REQUIREMENT LIFECYCLE → DECISION SEMANTICS CI-VALIDATED**.


## Investigation Explanation — Known / Unresolved / Blocked / Next

Status: **CI-validated and field-validated** on 2026-09-28 against the authorized lab target `192.168.227.138`.

The explanation layer is a projection of established investigation state. It does not run Nmap, re-run analysis, create findings, invent retries, or bypass authorization.

Source-of-truth mapping:
- `snapshot.states[].known` -> **Known** observed endpoint facts.
- Finding lifecycle evidence -> **Known** finding/evidence provenance.
- `snapshot.gaps` and non-terminal finding requirements -> **Unresolved**.
- Discovery failure, `pending_approval`, and `attempted_unsatisfied` -> **Blocked**.
- Before a final decision exists, `snapshot.actions` may supply **Next**.
- Once a `FinalInvestigationDecision` exists, only `final_decision.further_actions` may supply **Next**. Stale snapshot proposals must not be presented as currently justified actions.

Rendering and integration:
- Text renderer: `render_investigation_explanation`.
- JSON renderer: `render_investigation_explanation_json`.
- `investigation_explanation` is included in installed-package metadata.
- CLI builds the explanation from the freshest/final snapshot and passes the final decision when available.
- JSON keeps the explanation inside the existing investigation-continuation envelope rather than creating a competing top-level workflow.

Field validation exposed and then verified a semantic correction. After the primary HTTP collection (`http-title,http-methods`) returned incomplete evidence, the repeat guard blocked re-running it, the bounded alternative (`http-headers`) was attempted once and also returned incomplete, and the final decision was `stalled / alternative_evidence_incomplete` with zero further supported actions. The snapshot still contained the original proposed HTTP action, but the corrected Explanation rendered **Next** empty. No HTTP retry was invented and `smb-enum-shares` was not executed without explicit approval.

Field-validated final explanation included:
- observed RPC, NetBIOS, SMB, and HTTP endpoint facts under **Known**;
- the two unresolved HTTP evidence gaps plus `smb_access_control_context` under **Unresolved**;
- `smb_access_control_context — explicit approval required` under **Blocked**;
- no entry under **Next**.

Design note: `Adaptive Investigation Plan` currently reports the adaptive decision that existed before the bounded alternative round, so in the final combined text it can still display the already-executed `http-headers` alternative. `Final Investigation Decision` and `Investigation Explanation` represent the later/final state. This is a presentation/time-context distinction, not permission to re-run the action. If the CLI is later simplified, label or placement can make this temporal distinction clearer without changing reasoning semantics.

Milestone: **INVESTIGATION EXPLANATION — KNOWN / UNRESOLVED / BLOCKED / NEXT — FIELD VALIDATED**.


## Handoff — 2026-09-28 — Controller canonical finalization closure

Current verified baseline:
- Test suite: 799 tests.
- Latest CI-confirmed commit: `28622e87e1f27a92a6096f966de76cbfa09d2fff` (`Assert stop override returns canonical projection`).
- User reported CI green for that commit.
- The next attempted edit did NOT commit: an anchor lookup failed while trying to add a distinct-canonical-projection assertion to the explicit-approval finalization test. Repository state therefore remains at `28622e8...`.

Recent closure sequence, all CI green unless explicitly noted:
- `60aeaef` Assert unsatisfied source decision remains immutable.
- `3829b998` Assert alternative terminal status contract.
- `dfca342c` Assert stop override leaves source continuation immutable.
- `0045c033` Assert rejected finalization leaves continuation untouched.
- `9246dbc6` Assert finalizer returns distinct canonical decision (complete path).
- `3db5ddac` Assert stalled finalization returns canonical projection.
- `28622e87` Assert stop override returns canonical projection.

Important continuation point:
- Continue Controller/E2E closure autonomously.
- Inspect the actual current test text before patching; do not assume an anchor.
- Natural next target: explicit-approval and attempted-unsatisfied finding finalization should also prove that finalization returns a distinct canonical `FinalInvestigationDecision` while preserving source lifecycle identity/immutability.
- Do not guess `EvidenceRequirement` fields. Known valid fields used by tests: `requirement_id`, `purpose`. Previous guesses `script_ids` and `primary_script_id` caused CI failures and were removed.
- Keep the controller bounded/deterministic and preserve the canonical flow: Discover -> Analyze -> Gap -> Plan -> Authorize -> Collect -> Verify -> Re-plan -> STOP.

User workflow:
- Work directly in GitHub; user should not be asked to commit/push.
- Ask user only for CI green/red confirmation or when a genuine Kali field test is required.
- If green, continue automatically without summaries.
- If red, inspect GitHub Actions/logs, fix, push, then ask only green/red.
- No Codex.
- Operational responses should be very short and in Hebrew.


## Controller closure checkpoint — 2026-09-28

The bounded investigation Controller/final-decision contract has now been hardened through the alternative-evidence and finding-derived requirement paths.

Latest verified local regression baseline:

```text
Ran 801 tests in 0.382s

OK
```

Current main checkpoint: `74858079273f55302f61a8b2057b3be0427b253e`.

Verified invariants include:
- finalization returns a distinct canonical `FinalInvestigationDecision` projection rather than mutating/returning the source continuation object;
- source continuation state remains unchanged across complete, stalled, stop-override, pending-approval, and attempted-unsatisfied finalization paths;
- alternative evidence that semantically satisfies a primary requirement does not erase independent finding-derived lifecycle state;
- `pending_approval` still stalls with `explicit_approval_required`;
- `attempted_unsatisfied` still stalls with `finding_requirement_unsatisfied`;
- primary semantic requirements satisfied by alternative evidence are recorded in `satisfied_requirements` while unresolved finding requirements remain explicit;
- final decisions expose no further action after the bounded terminal round.

This closes the current Controller contract-hardening slice. Do not continue adding micro-tests to this area merely to increase coverage. The next development work should move outward to end-to-end product completion/field behavior unless a concrete Controller regression is discovered.


## E2E product-completion checkpoint — 2026-09-28

Current CI-confirmed main checkpoint before this documentation commit: `ab8574d12c9a6d36ccbefba268671b16f52462ef`.

The Controller micro-contract phase remains closed. Subsequent work moved outward into the completed collect workflow and public product boundary.

E2E changes now established on `main`:
- every completed `--investigate-collect` path exposes one canonical terminal `FinalInvestigationDecision`;
- investigation synthesis is mandatory after a completed collect workflow rather than optional downstream state;
- a bounded stalled investigation returns CLI success because it is a valid terminal product outcome; non-zero remains for discovery/processing failures;
- continuation text/JSON reporting uses the freshest final snapshot rather than stale pre-alternative state;
- `--adaptive-plan` reporting now projects the terminal state and cannot present an already-consumed alternative action as a current next action;
- final-decision JSON exposes remaining finding-derived lifecycle with endpoint, finding provenance, authorization state, lifecycle status, and observed scripts;
- regression coverage locks the terminal adaptive projection and final finding-lifecycle JSON contract;
- README now documents the bounded investigation workflow and the current Controller / Adaptive / Explanation / Synthesis / Memory architecture.

Relevant E2E commit sequence:
- `5e536b5` Guarantee terminal decision for collect workflow.
- `133fd55` Require synthesis for every completed collect workflow.
- `6e1fe1d` Clarify collect workflow exit semantics.
- `ebaae5d` Use final snapshot for continuation reporting.
- `e2af4e7` / `d7708bc` Report terminal adaptive investigation state and align its CLI contract.
- `fc6c32c` Lock terminal adaptive projection contract.
- `9d357b5` / `4c4de0f` Expose final finding lifecycle in JSON and align the JSON contract.
- `2b46ec3` Cover real pending-approval finding lifecycle JSON provenance.
- `75d82bb` Document bounded investigation workflow.
- `ab8574d` Document investigation architecture.

Important correction to the older Investigation Explanation handoff above: its note that Adaptive Investigation Plan may display a pre-alternative action is historical. That presentation gap has now been fixed; final adaptive reporting is terminal and action-free.

Next development direction: continue product-level E2E completion and field behavior. Do not reopen Controller micro-test expansion unless a concrete regression appears. A deliberate Kali field validation should be requested only when behavior cannot be validated meaningfully in CI.
