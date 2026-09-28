# Security Policy

## Reporting a vulnerability

If you discover a potential security vulnerability in NetRecon, please report it privately through GitHub's **Private Vulnerability Reporting** feature for this repository.

Please do **not** open a public GitHub issue for an undisclosed security vulnerability.

When possible, include:

- a clear description of the issue,
- the affected NetRecon version or commit,
- steps to reproduce the behavior,
- the potential security impact,
- and any suggested mitigation or fix.

Please avoid including credentials, private keys, secrets, personal information, or sensitive scan data in a report unless they are strictly necessary to demonstrate the issue.

## Scope

Security reports should concern vulnerabilities in NetRecon itself, its packaging, or its documented workflows.

Findings discovered by NetRecon in third-party systems are not vulnerabilities in NetRecon and should be handled according to the authorization and disclosure rules that apply to those systems.

## Responsible use

NetRecon can passively analyze existing Nmap XML and can also invoke Nmap for bounded discovery and evidence collection. Any workflow that targets a live system or network must be used only within the scope of authorization you already have.

NetRecon's requirement-scoped explicit approval controls whether certain supported collection actions may proceed inside the product. It is a workflow boundary, not a substitute for legal or organizational authorization to test the target.

Do not use the project to access, test, or disclose information from systems without appropriate authorization.

## Disclosure

Please allow reasonable time for a reported vulnerability to be investigated and addressed before public disclosure.

NetRecon was created and is maintained by Deeb Mzareb.
