# NetRecon Practical Training Findings

This file records findings discovered during authorized practical training. Findings remain open until they are implemented and verified by regression testing and a repeat practical test.

## F-001 — URL Target Normalization

**Status:** CLOSED

**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED. CI passed after the implementation. A repeat test in the isolated VMware lab using `netrecon --discovery-plan http://192.168.111.130:8180/` preserved URL context internally while the analyst-facing discovery plan correctly normalized the Nmap target to `192.168.111.130` and proposed `nmap -sV -oX - 192.168.111.130`.

**Observed:** NetRecon accepted a full HTTPS URL as a discovery target and passed the URL unchanged to Nmap.

**Example input:**
`https://<host>/`

**Current behavior:**
`nmap -sV -oX - https://<host>/`

**Expected direction:** Parse URL targets before planning or execution. Preserve relevant URL context (scheme, hostname, explicit/implicit port, and path), while supplying Nmap with a valid hostname/IP target.

## F-002 — Web-Aware Discovery

**Status:** CLOSED

**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED. CI passed after the implementation. In the isolated VMware lab, `netrecon --discover http://192.168.111.130:8180/` selected the `web` discovery profile and executed the bounded command `nmap -sV -p 8180 -oX - 192.168.111.130`. Discovery completed successfully and identified 8180/tcp as HTTP running Apache Tomcat/Coyote JSP engine 1.1.

**Observed:** A target explicitly supplied as an HTTPS URL entered the generic baseline discovery path (`nmap -sV` across Nmap's default ports). The HTTPS application itself was reachable with a normal HTTP client, while the Nmap discovery path did not complete in a useful time.

**Expected direction:** Evaluate a Web-aware discovery path for URL/HTTP(S) targets. Web evidence collection (HTTP status, headers, TLS and related metadata) should not necessarily depend on completion of generic network-service discovery.

## F-003 — Discovery Timeout Handling

**Status:** CLOSED

**Observed:** `netrecon --discover <host>` ended with `Nmap discovery timed out`. A direct HTTPS request to the same authorized lab target returned promptly, while direct Nmap attempts did not produce a completed host/ports result.

**Expected direction:** Distinguish collector timeout from target unreachability, retain useful partial/context evidence where appropriate, and evaluate safe fallback/alternative collection paths instead of treating all discovery timeouts as equivalent failures.


**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED. CI passed after timeout provenance and reporting support were added. In the isolated VMware lab, `netrecon --discover http://192.168.111.130:8180/ --evidence-timeout 0.001` produced a bounded timeout with `Failure kind: collector_timeout` and `Target unreachable: no`, demonstrating that a collector timeout is no longer mislabeled as target unreachability. Partial stdout/stderr retention is covered by regression tests when such output exists.

## F-004 — Authenticated SMB Evidence Collection

**Status:** CLOSED

**Observed:** In the Windows lab, the approval-gated `smb-enum-shares` NSE path could not collect the requested authenticated SMB access-control evidence against a modern SMB2/SMB3 target. Direct validation showed that the authorized account could enumerate shares with `smbclient`, isolating the limitation to the NSE collection path rather than the credentials or target.

**Expected direction:** Add an authorized authenticated SMB evidence path with explicit credential handling, clear separation between anonymous and authenticated evidence, and no credentials written into reports or command history.

**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED. NetRecon now uses an SMB2/SMB3-capable `smbclient` collection path for explicitly approved authenticated share evidence while preserving the existing finding-requirement lifecycle. Credentials are read from the existing credentials file, passed through a temporary mode-0600 authentication file, excluded from argv/report output, and the temporary file is removed after collection. The full regression suite passed 856/856 tests. In the isolated Windows lab, `--investigate-collect` with explicit approval completed the authenticated dynamic evidence round successfully; `smb_access_control_context` became `satisfied`, `smb-enum-shares` evidence was observed, and the final investigation reported zero remaining finding requirements.

## F-005 — Investigation Coverage Is Narrower Than Service Discovery

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, baseline discovery found 23 open ports / 20 unique services, but the investigation planner initially created only five evidence gaps covering SSH and two HTTP services. Numerous other discovered services had no protocol-specific evidence requirements or follow-up collection plan.

**Expected direction:** Expand protocol-aware investigation rules and evidence collectors so that supported services can generate meaningful evidence requirements rather than merely appearing in the inventory.

**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED. Coverage was expanded for FTP, SMTP, NFS, rpcbind, MySQL, and VNC through the planner, evidence gaps, semantic requirements, and bounded action planning. CI passed after each implementation stage. In the isolated Metasploitable lab, `netrecon --investigate 192.168.111.130` increased the investigation from the original five gaps to 14 evidence gaps and 10 proposed actions. A subsequent `--investigate-collect` run satisfied 11 semantic requirements, including the newly added FTP (port 21), SMTP, rpcbind, MySQL, and VNC requirements, while correctly leaving three requirements unresolved instead of overstating completion. The remaining NFS export requirement and FTP requirements on port 2121 are collection-specific limitations tracked separately by F-010 and F-011. Manual verification showed that NFS export evidence becomes observable when rpcbind (111/tcp) is included with service detection, while the bounded 2049-only action produced no `nfs-showmount` output. For FTP on 2121/tcp, service detection correctly identified ProFTPD 1.3.1, but `ftp-syst` and `ftp-anon` produced no script evidence even when tested separately with `-sV`.

## F-006 — Completion Semantics Can Overstate Investigation Coverage

**Status:** CLOSED

**Observed:** The Metasploitable investigation ended with `Status: complete`, `Reason: all_gaps_resolved`, and zero remaining requirements after resolving the requirements known to the current planner. This did not mean all discovered services were investigated in depth.

**Expected direction:** Make completion language scope-aware. Distinguish “all currently supported/planned requirements resolved” from “target investigation complete” so users do not interpret planner completeness as comprehensive target coverage.

**Verification:** IMPLEMENTED → REGRESSION TESTED. Terminal completion retains the stable `Status: complete` API value but now reports `Reason: all_supported_requirements_resolved` when no supported requirements remain. The distinct `all_semantic_requirements_satisfied` reason is preserved when alternative evidence satisfies semantic requirements while raw gaps remain. Stalled outcomes such as `explicit_approval_required` remain unchanged, as confirmed by the Windows SMB lab. The full regression suite passed 856/856 tests.

## F-007 — Default Investigation Report Is Too Verbose and Repetitive

**Status:** CLOSED

**Observed:** `--investigate-collect` repeated substantially the same information across Continuation Decision, Semantic Requirement Progress, Final Investigation Decision, Investigation Snapshot, Investigation Explanation, and Investigation Synthesis. The full service inventory was also repeated.

**Expected direction:** Make the default report concise and decision-oriented. Show target/status, important findings/attention, unresolved requirements, and correlated review without repeating the investigation lifecycle. Move detailed evidence/state/explanation sections behind a detail mode.

**Verification:** IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VALIDATED. Text `--investigate-collect` now renders a concise `Investigation Summary` by default. The previous full evidence/provenance report remains available with `--detail`. JSON output remains structurally unchanged. Full regression suite passed 857/857 tests. Windows lab validation confirmed both concise default output and restored full detail output.

## F-008 — Attention Prioritization and Correlation Need Improvement

**Status:** CLOSED

**Observed:** The Metasploitable run produced 10 Analyst Attention items but zero Correlated Review groups. Attention mixed transport exposure, missing product identification, legacy configuration evidence, and duplicated/related service observations without a compact priority/correlation view.

**Resolution:** Analyst Attention now uses deterministic evidence-review ordering without adding risk scores or changing finding severity: configuration, transport, exposure, then visibility. Correlation now groups multiple FTP service instances on the same host and related 139/tcp + 445/tcp SMB/NetBIOS transport exposure while preserving the original scanner-derived findings and service labels. The existing SMB exposure + signing correlation remains supported.

**Validation:** Full regression suite passed 860/860 tests. Practical validation against the isolated Metasploitable2 lab retained 10 traceable Attention items, placed the legacy SSH configuration evidence before transport/exposure/visibility notes, and produced two Correlated Review groups: multiple FTP instances and related SMB/NetBIOS transport exposure. Service-label interpretation remains intentionally deferred to F-009.

## F-009 — Service Identity/Protocol Labeling Needs Review

**Status:** CLOSED

**Observed:** Both 139/tcp and 445/tcp were presented as `netbios-ssn`/“NetBIOS session service exposed” in the Metasploitable report. The underlying discovery identified Samba on both ports, but the analyst-facing label risked obscuring the SMB context of 445/tcp.

**Implemented:** Service interpretation now uses the well-known transport context to distinguish the two analyst-facing roles without rewriting scanner evidence. A `netbios-ssn` label on 139/tcp remains “NetBIOS session service exposed”; the same raw label on 445/tcp is presented as “SMB service exposed”. The evidence text continues to preserve Nmap's original `netbios-ssn` identification. F-008 correlation was updated so the 139/tcp NetBIOS finding and 445/tcp SMB finding remain jointly reviewed.

**Validation:** Focused service-rule and analyst-attention tests passed, followed by the full regression suite. Practical Metasploitable2 validation showed 139/tcp as NetBIOS, 445/tcp as SMB while retaining `identified as netbios-ssn`, and restored the expected two correlated-review groups (multiple FTP instances plus related NetBIOS/SMB transport exposure).

## F-010 — NFS Export and Access Evidence Collection

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, NetRecon discovered NFS on 2049/tcp but initially did not create an NFS-specific evidence requirement. Manual validation showed that Nmap's `nfs-showmount` collector could observe the root export (`/ *`), while `nfs-ls` could enumerate the exported volume and report observed access capabilities including Read, Lookup, Modify, Extend, and Delete. A read-only manual mount independently confirmed that the exported volume exposed the target filesystem. Reading `/etc/exports` provided additional ground truth showing `/ *(rw,sync,no_root_squash,no_subtree_check)`; those server-side options must not be inferred solely from `nfs-showmount` or `nfs-ls`.

**Implemented:** NetRecon now creates the semantic `nfs_export_context` requirement for discovered NFS services and plans `nfs-showmount`. When an open rpcbind service is present, the bounded NFS action includes RPC context and service detection (`-sV -p 111,2049` in the lab). Cross-port recognition is deliberately scoped to non-empty `nfs-showmount` evidence, allowing evidence emitted on the related rpcbind endpoint to satisfy the NFS requirement without making evidence matching generally cross-port.

**Regression tested:** TDD covered RPC-aware NFS action planning and the cross-port case where `nfs-showmount` is emitted on rpcbind while the semantic requirement remains bound to NFS/2049. CI passed after both implementation changes.

**Practically verified:** On the isolated Metasploitable target, `netrecon --investigate-collect` executed `nmap -sV -p 111,2049 --script nfs-showmount -oX - <target>`, reported `Requested Evidence: observed`, resolved `nfs_export_context` on 2049/tcp, and left only the two independent FTP requirements on 2121/tcp. This confirms the NFS planner, collector execution path, cross-port evidence recognition, and semantic-resolution path operate together.

**Evidence boundary:** Closure covers NFS export/client-scope context through `nfs-showmount`. Access/content observations from `nfs-ls` and server-side options such as `no_root_squash` remain separate evidence and must not be inferred from `nfs-showmount`.


## F-011 — FTP Access and Transport Evidence Collection

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, FTP evidence behaved differently across endpoints. On 21/tcp, Nmap `ftp-anon` and `ftp-syst` directly supplied the requested evidence. On ProFTPD 1.3.1 at 2121/tcp, the corrected `nmap -sV -p 2121 --script ftp-syst,ftp-anon` collection completed successfully but produced no requested NSE evidence.

**Implemented:** NetRecon now requests FTP evidence with service detection enabled and preserves the original NSE evidence gaps when those scripts remain silent. After the primary action is repeat-exhausted, a bounded protocol-level FTP alternative can collect the welcome banner, `SYST`, `STAT`, and one anonymous-login observation. Anonymous access is recorded as `allowed`, `denied`, or `unknown`; no password candidates or brute-force behavior are used. Protocol evidence remains distinct from NSE `ScriptResult` provenance.

**Regression tested:** Collector normalization, bounded collection planning/execution, protocol-alternative planning, execution, semantic round handling, terminal semantic decision, CLI orchestration, packaging, and analyst-facing reporting are covered by regression tests. The full CI suite was GREEN before practical verification.

**Practically verified:** On 192.168.111.130:2121/tcp, primary NSE collection remained incomplete for `ftp-syst` and `ftp-anon`. NetRecon then executed the protocol alternative and observed anonymous login as `denied`, `SYST: UNIX Type: L8`, and `STAT: Please login with USER and PASS`. Both semantic requirements (`ftp_anonymous_access`, `ftp_system_context`) were satisfied while both original NSE gaps were explicitly preserved. The final semantic decision was `complete / all_semantic_requirements_satisfied`.

**Evidence boundary:** A denied anonymous login is evidence about anonymous-access behavior, not evidence of authenticated access. `SYST`/`STAT` responses provide protocol/server context only. Preserved NSE gaps continue to state that the requested NSE scripts themselves did not return evidence.


## F-012 — SMTP Capability Evidence Collection

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, NetRecon discovered SMTP on 25/tcp and identified Postfix smtpd. Existing F-005 evidence planning already created the `smtp_capability_context` semantic requirement and proposed `smtp-commands`; F-012 identified the remaining gap: successfully collected `smtp-commands` evidence was not interpreted into analyst-facing SMTP capability intelligence.

**Implemented:** Added semantic interpretation of `smtp-commands` NSE evidence. NetRecon now creates the informational finding `smtp.capabilities.inventory` / `SMTP capability inventory collected` and surfaces the advertised SMTP capabilities while preserving NSE provenance as `nse:smtp-commands`.

**Practically verified:** On 192.168.111.130:25/tcp, `smtp-commands` successfully observed PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, and DSN. `netrecon --analyze` surfaced the new SMTP capability inventory finding. The full `--investigate-collect` workflow successfully collected the requested SMTP evidence, resolved `smtp_capability_context`, and reached the final semantic decision `complete / all_semantic_requirements_satisfied`.

**Evidence boundary:** Advertised SMTP capabilities are protocol context only. In particular, observing STARTTLS means that the SMTP server advertised STARTTLS; it does not establish that TLS was negotiated or that certificate, protocol, cipher, or other TLS security properties were validated.

**Validation:** Added focused tests for SMTP capability inventory and the STARTTLS evidence boundary. The NSE rule suite passed 18/18 tests and the full NetRecon regression suite passed 846/846 tests.

## F-013 — RPC Service Mapping and Correlation

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, NetRecon already had the RPC evidence-planning path introduced earlier: discovered rpcbind services create the semantic `rpc_service_mapping` requirement and plan `rpcinfo`. Practical validation showed that `rpcinfo` returned a richer RPC service map containing RPC program numbers, supported versions, TCP/UDP transports, and mapped ports for rpcbind, NFS, mountd, nlockmgr, and status. The remaining F-013 gap was semantic interpretation: the collected mapping was preserved as raw NSE output but was not surfaced as an analyst-facing RPC finding.

**Implemented:** Added protocol-aware interpretation of `rpcinfo` evidence. NetRecon now emits the informational `rpc.service.mapping` finding and preserves the observed RPC program, version, transport, mapped-port, and service context. The recommendation explicitly preserves provenance: services learned through rpcbind mapping data are not treated as independently discovered open ports without separate supporting evidence.

**Correlation boundary:** RPC program-to-service mapping is retained as protocol context rather than promoted into Analyst Attention. Existing Analyst Attention correlation is intentionally limited to review-worthy finding categories. F-013 therefore does not broaden that architecture merely to correlate informational RPC context.

**Practical verification:** An authorized lab scan of rpcbind on 111/tcp with `rpcinfo` reported RPC program 100003 for NFS, 100005 for mountd, 100021 for nlockmgr, and 100024 for status, across observed TCP/UDP mappings. NetRecon surfaced the new `RPC service mapping collected` finding while the Network Summary continued to report only the independently scanned 111/tcp rpcbind endpoint as open.

**Validation:** Added a focused TDD test for RPC service-map interpretation. The test failed before implementation and passed after the rule was added. The full NetRecon regression suite passed 847/847 tests.

## F-014 — MySQL Protocol Capability Evidence Collection

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, NetRecon already had the MySQL evidence-planning path introduced earlier: discovered MySQL services create the semantic `mysql_capability_context` requirement and plan `mysql-info`. Practical validation on 3306/tcp reported MySQL protocol version 10, server version 5.0.51a-3ubuntu5, capability flags, advertised capabilities including `SwitchToSSLAfterHandshake`, and status `Autocommit`. The remaining F-014 gap was semantic interpretation of the collected NSE evidence.

**Implemented:** Added protocol-aware interpretation of `mysql-info`. NetRecon now emits the informational `mysql.capabilities.inventory` finding and retains protocol version, server version, capability flags, advertised capabilities, and status context. Low-value ephemeral handshake fields such as Thread ID and Salt are omitted from the default analyst-facing evidence.

**Evidence boundary:** An advertised capability such as `SwitchToSSLAfterHandshake` is retained as protocol context only. It does not establish that TLS was negotiated or that its security properties were validated.

**Practical verification:** An authorized lab scan of MySQL on 3306/tcp reported Protocol 10, Version 5.0.51a-3ubuntu5, capability flags 43564, multiple advertised capabilities, and Autocommit status. The implementation was validated against this observed output shape.

**Validation:** Added a focused test for MySQL capability interpretation and ephemeral-field filtering. The regression suite passed 848/848 tests.

## F-015 — VNC Protocol and Security Evidence Collection

**Status:** CLOSED

**Observed:** In the isolated Metasploitable lab, NetRecon already had the VNC evidence-planning path introduced earlier: discovered VNC services create the semantic `vnc_security_context` requirement and plan `vnc-info`. Practical validation on 5900/tcp reported VNC protocol version 3.3 and the advertised security type `VNC Authentication (2)`. The remaining F-015 gap was semantic interpretation of the collected NSE evidence.

**Implemented:** Added protocol-aware interpretation of `vnc-info`. NetRecon now emits the informational `vnc.security.context` finding and retains the observed VNC protocol version and advertised security types.

**Evidence boundary:** Observing `VNC Authentication (2)` is retained as advertised service context only. It does not establish password strength, credential validity, or successful authenticated access.

**Practical verification:** An authorized lab scan of VNC on 5900/tcp reported Protocol version 3.3 and Security type `VNC Authentication (2)`. The implementation was validated against this observed output shape.

**Validation:** Added a focused test for VNC protocol and security-context interpretation. The regression suite passed 849/849 tests.

## Practical observations worth preserving

- NetRecon successfully separated discovery from investigation and generated targeted evidence collection rather than blindly repeating broad scans.
- In the Metasploitable lab, all five planned SSH/HTTP evidence requirements were successfully collected and resolved.
- The evidence discipline remains useful: a successful collector return code is not treated as proof that requested evidence was observed.
- The practical lab is revealing the difference between “services NetRecon can see” and “services NetRecon knows how to investigate”; this should remain a central development test.
- NFS practical validation confirmed that existing Nmap NSE collectors can provide useful export and access evidence without requiring a new external collector for the first implementation.
- Default output should optimize for analyst decisions; detailed evidence should remain available on demand.
- Practical verification should continue to compare NetRecon conclusions with direct/manual ground truth before closing findings.

## Verification workflow

For each finding:

`OPEN → IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED → CLOSED`

Do not close a finding solely because code changed; repeat the relevant practical scenario.
