"""Bounded, protocol-level FTP evidence primitives.

Missing replies remain unknown; an explicit FTP denial is still observed
evidence about anonymous-access behavior.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FtpProtocolEvidence:
    """Normalized read-only FTP protocol evidence."""

    banner: str | None = None
    syst: str | None = None
    stat: str | None = None
    anonymous_login: str = "unknown"


def _observed_text(code: int | None, value: str) -> str | None:
    """Keep non-empty text only when an FTP reply code was observed."""
    text = value.strip()
    if code is None or not text:
        return None
    return text


def _anonymous_status(code: int | None) -> str:
    """Classify one anonymous-login reply without guessing."""
    if code == 230:
        return "allowed"
    if code is not None and 500 <= code <= 599:
        return "denied"
    return "unknown"


def parse_ftp_protocol_evidence(
    *,
    banner_code: int | None,
    banner: str,
    syst_code: int | None,
    syst: str,
    stat_code: int | None,
    stat: str,
    anonymous_code: int | None,
    anonymous_message: str,
) -> FtpProtocolEvidence:
    """Normalize bounded FTP replies into explicit evidence states."""
    _ = anonymous_message
    return FtpProtocolEvidence(
        banner=_observed_text(banner_code, banner),
        syst=_observed_text(syst_code, syst),
        stat=_observed_text(stat_code, stat),
        anonymous_login=_anonymous_status(anonymous_code),
    )

@dataclass(frozen=True)
class FtpProtocolCollectionPlan:
    """Bounded read-only FTP protocol collection plan."""

    host: str
    port: int
    timeout: float | None
    commands: tuple[str, ...] = ("SYST", "STAT")
    check_anonymous: bool = True


def build_ftp_protocol_collection_plan(
    host: str,
    port: int,
    *,
    timeout: float | None = None,
) -> FtpProtocolCollectionPlan:
    """Build a fixed, read-only FTP evidence plan for one endpoint."""
    normalized_host = host.strip()
    if not normalized_host:
        raise ValueError("FTP collection requires a host")
    if not 1 <= port <= 65535:
        raise ValueError("FTP collection requires a valid TCP port")
    return FtpProtocolCollectionPlan(
        host=normalized_host,
        port=port,
        timeout=timeout,
    )
