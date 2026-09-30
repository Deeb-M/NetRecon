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

**Status:** OPEN

**Observed:** `netrecon --discover <host>` ended with `Nmap discovery timed out`. A direct HTTPS request to the same authorized lab target returned promptly, while direct Nmap attempts did not produce a completed host/ports result.

**Expected direction:** Distinguish collector timeout from target unreachability, retain useful partial/context evidence where appropriate, and evaluate safe fallback/alternative collection paths instead of treating all discovery timeouts as equivalent failures.

## F-004 — Authenticated SMB Evidence Collection

**Status:** OPEN

**Observed:** In the Windows lab, the approval-gated `smb-enum-shares` collection completed successfully at the collector/process level but the requested SMB access-control evidence was not observed. Manual anonymous SMB enumeration was denied. This exposed a limitation in the current evidence workflow when useful SMB evidence requires authenticated collection.

**Expected direction:** Add an authorized authenticated SMB evidence path with explicit credential handling, clear separation between anonymous and authenticated evidence, and no credentials written into reports or command history.

## F-005 — Investigation Coverage Is Narrower Than Service Discovery

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, baseline discovery found 23 open ports / 20 unique services, but the investigation planner created only five evidence gaps covering SSH and two HTTP services. Numerous other discovered services had no protocol-specific evidence requirements or follow-up collection plan.

**Expected direction:** Expand protocol-aware investigation rules and evidence collectors so that supported services can generate meaningful evidence requirements rather than merely appearing in the inventory.

## F-006 — Completion Semantics Can Overstate Investigation Coverage

**Status:** OPEN

**Observed:** The Metasploitable investigation ended with `Status: complete`, `Reason: all_gaps_resolved`, and zero remaining requirements after resolving the five requirements known to the current planner. This does not mean all discovered services were investigated in depth.

**Expected direction:** Make completion language scope-aware. Distinguish “all currently supported/planned requirements resolved” from “target investigation complete” so users do not interpret planner completeness as comprehensive target coverage.

## F-007 — Default Investigation Report Is Too Verbose and Repetitive

**Status:** OPEN

**Observed:** `--investigate-collect` repeated substantially the same information across Continuation Decision, Semantic Requirement Progress, Final Investigation Decision, Investigation Snapshot, Investigation Explanation, and Investigation Synthesis. The full service inventory was also repeated.

**Expected direction:** Make the default report concise and decision-oriented. Show target/status, service summary, collection outcomes, important findings/attention, unresolved requirements, and next actions once. Move detailed evidence/state/explanation sections behind a verbose/detail mode.

## F-008 — Attention Prioritization and Correlation Need Improvement

**Status:** OPEN

**Observed:** The Metasploitable run produced 10 Analyst Attention items but zero Correlated Review groups. Attention mixed transport exposure, missing product identification, legacy configuration evidence, and duplicated/related service observations without a compact priority/correlation view.

**Expected direction:** Improve evidence-based grouping and prioritization without inventing severity. Correlate related ports/services and distinguish actionable configuration/exposure evidence from lower-value visibility notes.

## F-009 — Service Identity/Protocol Labeling Needs Review

**Status:** OPEN

**Observed:** Both 139/tcp and 445/tcp were presented as `netbios-ssn`/“NetBIOS session service exposed” in the Metasploitable report. The underlying discovery identified Samba on both ports, but the analyst-facing label risks obscuring the SMB context of 445/tcp.

**Expected direction:** Preserve raw scanner evidence while presenting protocol/service context accurately and consistently. Avoid analyst-facing labels that can make distinct transport/service roles look identical.

## F-010 — NFS Export and Access Evidence Collection

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered NFS on 2049/tcp but did not create an NFS-specific evidence requirement. Manual validation showed that Nmap's `nfs-showmount` collector could observe the root export (`/ *`), while `nfs-ls` could enumerate the exported volume and report observed access capabilities including Read, Lookup, Modify, Extend, and Delete. A read-only manual mount independently confirmed that the exported volume exposed the target filesystem. Reading `/etc/exports` provided additional ground truth showing `/ *(rw,sync,no_root_squash,no_subtree_check)`; those server-side options must not be inferred solely from `nfs-showmount` or `nfs-ls`.

**Expected direction:** Add protocol-aware NFS evidence requirements and collectors. A detected NFS service should be able to request export context via `nfs-showmount` and, where authorized and appropriate, access/content context via `nfs-ls`. Preserve evidence boundaries: report only export/access properties actually observed by each collector and do not infer server-side export options that were not directly evidenced.


## F-011 — FTP Access and Transport Evidence Collection

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered FTP on 21/tcp and identified vsFTPd 2.3.4, but its analyst-facing investigation stopped at the generic FTP exposure observation. Manual Nmap validation showed that `ftp-anon` directly observed anonymous login as allowed (FTP code 230), while `ftp-syst` reported service/system context and that both control and data connections were plain text. A separate manual anonymous FTP session confirmed successful login and a successful directory-listing operation; no filenames were returned by that listing.

**Expected direction:** Add protocol-aware FTP evidence requirements for access and transport context. A detected FTP service should be able to request anonymous-access evidence via `ftp-anon` and service/transport context via `ftp-syst`. Preserve evidence boundaries: distinguish an allowed anonymous login from the content actually visible through that session, and do not infer files or permissions that were not observed.


## F-012 — SMTP Capability Evidence Collection

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered SMTP on 25/tcp and identified Postfix smtpd, but did not create an SMTP-specific evidence requirement. Manual Nmap validation with `smtp-commands` observed the advertised SMTP identity/capabilities: `metasploitable.localdomain`, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, and DSN. Follow-up runs using generic TLS scripts and `smtp-ntlm-info` returned no additional evidence.

**Expected direction:** Add protocol-aware SMTP capability evidence collection using `smtp-commands`. Preserve evidence boundaries: an advertised capability such as STARTTLS is evidence that the server announces that capability, not proof that TLS properties were successfully collected or validated. Treat collectors that return no requested evidence as incomplete/unsatisfied rather than inferring a result.

## F-013 — RPC Service Mapping and Correlation

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered rpcbind on 111/tcp but did not create an RPC-specific evidence requirement. Manual Nmap validation with `rpcinfo` exposed a richer RPC service map, including RPC program numbers, supported versions, TCP/UDP transports, and dynamically assigned ports for related services such as NFS, mountd, nlockmgr, and status.

**Expected direction:** Add protocol-aware RPC service mapping using `rpcinfo` and correlate observed RPC programs, versions, transports, and dynamic ports with related discovered services. Preserve the distinction between the rpcbind endpoint itself and services learned through its mapping data.

## F-014 — MySQL Protocol Capability Evidence Collection

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered MySQL on 3306/tcp and identified MySQL 5.0.51a-3ubuntu5, but did not create a MySQL-specific evidence requirement. Manual Nmap validation with `mysql-info` observed protocol version 10, server version, protocol capability flags, and status information including Autocommit. The collector also reported that the server advertised `SwitchToSSLAfterHandshake`.

**Expected direction:** Add protocol-aware MySQL handshake/capability evidence collection using `mysql-info`. Surface useful protocol version, server version, capability, and status context while omitting low-value ephemeral fields from default analyst output. Preserve evidence boundaries: an advertised capability such as `SwitchToSSLAfterHandshake` is not proof that transport security was successfully negotiated or validated.

## F-015 — VNC Protocol and Security Evidence Collection

**Status:** OPEN

**Observed:** In the isolated Metasploitable lab, NetRecon discovered VNC on 5900/tcp but did not create a VNC-specific evidence requirement. Manual Nmap validation with `vnc-info` observed VNC protocol version 3.3 and the advertised security type `VNC Authentication (2)`.

**Expected direction:** Add protocol-aware VNC evidence collection using `vnc-info`. Surface the observed protocol version and advertised security types. Preserve evidence boundaries: observing `VNC Authentication (2)` does not establish password strength, credential validity, or successful authenticated access.

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
