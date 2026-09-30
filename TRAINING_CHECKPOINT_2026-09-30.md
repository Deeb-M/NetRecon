# Practical Training Checkpoint — 2026-09-30

## Stable starting point

- Main commit: `521c0b8` — F-009 clarify SMB and NetBIOS service identity.
- Practical findings F-004 through F-015 are closed.
- The latest focused and full regression tests were green before the final practical validation.
- Windows 10 and Metasploitable2 remain the controlled VMware lab targets.

## Post-F-009 practical verification

Metasploitable2 was exercised again with the normal user workflow:

1. `netrecon --discover TARGET`
   - Discovery succeeded.
   - 23 open ports and 20 unique services were observed.
   - Raw Nmap service labels were preserved, including `netbios-ssn` on both 139/tcp and 445/tcp.

2. `netrecon --investigate TARGET`
   - Status: `ready`.
   - 14 evidence gaps.
   - 10 proposed collection actions.
   - Planner-supported coverage included FTP, SSH, SMTP, HTTP, RPC, NFS, MySQL, and VNC.
   - Other discovered services remain outside the currently supported evidence-planning scope; this is not treated as comprehensive target coverage.

3. `netrecon --investigate-collect TARGET`
   - Status: `complete`.
   - Reason: `all_semantic_requirements_satisfied`.
   - 0 remaining requirements.
   - 0 remaining finding requirements.
   - 10 Analyst Attention items.
   - 2 Correlated Review groups.
   - F-009 behavior remained correct: 139/tcp was presented as NetBIOS, 445/tcp as SMB, while raw `netbios-ssn` evidence was retained.
   - F-008 correlation remained intact: the NetBIOS and SMB findings were jointly reviewed.

## CLI learning checkpoint

The current CLI exposes 14 primary workflow modes:

- Target workflows: `--discovery-plan`, `--discover`, `--investigate`, `--investigate-collect`.
- Existing-XML workflows: `--analyze`, `--attention`, `--collect-evidence`, `--evidence-gaps`, `--evidence-actions`.
- Comparison workflows: `--diff`, `--analysis-diff`, `--combined-diff`.
- History workflows: `--history`, `--finding-history`.

Key distinction learned during training:

- `--discover TARGET`: discover what is present.
- `--investigate TARGET`: discover and show what supported evidence is still missing and what actions are proposed, without executing those evidence actions.
- `--investigate-collect TARGET`: discover, plan, collect supported evidence, re-evaluate, and report the terminal investigation result.
- Existing XML can be analyzed without launching a new discovery scan.

## XML persistence observation — candidate usability improvement

Current target discovery executes Nmap with `-oX -`, so the XML is consumed by NetRecon through process output rather than automatically retained as a normal user-owned XML file.

A user who specifically wants a persistent baseline XML currently has a clear manual path:

```bash
nmap -sV -oX scan.xml TARGET
netrecon scan.xml --analyze
```

Candidate improvement to evaluate later: allow a target-based NetRecon workflow to optionally save the underlying Nmap XML, for example through an explicit output option. This is a usability candidate, not yet an F-numbered defect and not yet an implementation decision.

Do not confuse this with `--investigation-history FILE`: investigation history persists completed synthesis records in append-only JSONL; it is not a replacement for retaining raw Nmap XML evidence.

## Next session

1. Continue the CLI command-selection exercises from the XML/evidence workflow.
2. Exercise `--evidence-gaps`, `--evidence-actions`, and `--collect-evidence` on a retained XML file.
3. Exercise comparison workflows with two controlled scans.
4. Exercise `--history`, `--finding-history`, and `--investigation-history`.
5. Evaluate the XML-save usability candidate through practical use before deciding whether to create F-016.
6. Continue looking for improvements through practical exercises before starting new development.
