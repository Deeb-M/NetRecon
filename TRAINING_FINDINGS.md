# NetRecon Practical Training Findings

This file records findings discovered during authorized practical training. Findings remain open until they are implemented and verified by regression testing and a repeat practical test.

## F-001 — URL Target Normalization

**Status:** OPEN

**Observed:** NetRecon accepted a full HTTPS URL as a discovery target and passed the URL unchanged to Nmap.

**Example input:**
`https://<host>/`

**Current behavior:**
`nmap -sV -oX - https://<host>/`

**Expected direction:** Parse URL targets before planning or execution. Preserve relevant URL context (scheme, hostname, explicit/implicit port, and path), while supplying Nmap with a valid hostname/IP target.

## F-002 — Web-Aware Discovery

**Status:** OPEN

**Observed:** A target explicitly supplied as an HTTPS URL entered the generic baseline discovery path (`nmap -sV` across Nmap's default ports). The HTTPS application itself was reachable with a normal HTTP client, while the Nmap discovery path did not complete in a useful time.

**Expected direction:** Evaluate a Web-aware discovery path for URL/HTTP(S) targets. Web evidence collection (HTTP status, headers, TLS and related metadata) should not necessarily depend on completion of generic network-service discovery.

## F-003 — Discovery Timeout Handling

**Status:** OPEN

**Observed:** `netrecon --discover <host>` ended with `Nmap discovery timed out`. A direct HTTPS request to the same authorized lab target returned promptly, while direct Nmap attempts did not produce a completed host/ports result.

**Expected direction:** Distinguish collector timeout from target unreachability, retain useful partial/context evidence where appropriate, and evaluate safe fallback/alternative collection paths instead of treating all discovery timeouts as equivalent failures.

## Verification workflow

For each finding:

`OPEN → IMPLEMENTED → REGRESSION TESTED → PRACTICALLY VERIFIED → CLOSED`

Do not close a finding solely because code changed; repeat the relevant practical scenario.
