"""Collect authenticated SMB share evidence with an SMB2/SMB3-capable client."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import tempfile

from evidence_collector import CollectionResult, NmapCommand, ParsedCollectionResult
from models import Host, Port, Scan, ScriptResult


def _read_nmap_smb_credentials(path: str) -> tuple[str, str, str | None]:
    """Read the existing NetRecon/Nmap SMB credential file without exposing secrets."""
    values: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()

    username = values.get("smbusername", "")
    password = values.get("smbpassword", "")
    domain = values.get("smbdomain") or None
    if not username or not password:
        raise ValueError("SMB credentials file requires smbusername and smbpassword")
    return username, password, domain


def collect_authenticated_smb_shares(
    target: str,
    port: int,
    credentials_file: str,
    *,
    timeout: float | None = None,
) -> ParsedCollectionResult:
    """Collect share names through smbclient while keeping credentials out of argv/output."""
    username, password, domain = _read_nmap_smb_credentials(credentials_file)

    auth_lines = [f"username = {username}", f"password = {password}"]
    if domain:
        auth_lines.append(f"domain = {domain}")

    auth_path: str | None = None
    safe_command = NmapCommand(
        arguments=("smbclient", "-g", "-L", f"//{target}", "-A", "<credentials-file>")
    )
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="netrecon-smb-",
            delete=False,
        ) as handle:
            auth_path = handle.name
            handle.write("\n".join(auth_lines) + "\n")
        os.chmod(auth_path, 0o600)

        completed = subprocess.run(
            ("smbclient", "-g", "-L", f"//{target}", "-A", auth_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        result = CollectionResult(safe_command, 1, "", str(exc))
        return ParsedCollectionResult(result=result, scan=None)
    finally:
        if auth_path:
            try:
                os.unlink(auth_path)
            except FileNotFoundError:
                pass

    result = CollectionResult(
        command=safe_command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
    if completed.returncode != 0:
        return ParsedCollectionResult(result=result, scan=None)

    shares: list[str] = []
    for raw_line in completed.stdout.splitlines():
        parts = raw_line.split("|", 2)
        if len(parts) < 2:
            continue
        share_type, share_name = parts[0].strip(), parts[1].strip()
        if share_name and share_type.lower() in {"disk", "ipc", "printer"}:
            shares.append(share_name)

    if not shares:
        return ParsedCollectionResult(result=result, scan=None)

    evidence = "collection_method: authenticated_smbclient\nshares: " + ", ".join(shares)
    scan = Scan(
        source="authenticated smbclient evidence",
        hosts=(
            Host(
                address=target,
                status="up",
                ports=(
                    Port(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service="microsoft-ds",
                        scripts=(ScriptResult("smb-enum-shares", evidence),),
                    ),
                ),
            ),
        ),
    )
    return ParsedCollectionResult(result=result, scan=scan)
