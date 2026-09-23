"""Core data models used by NetRecon."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Port:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    detection_method: str | None = None
    confidence: int | None = None


@dataclass(frozen=True)
class Host:
    address: str
    status: str
    hostname: str | None = None
    addresses: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    hostnames: tuple[str, ...] = field(default_factory=tuple)
    ports: tuple[Port, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Scan:
    source: str
    hosts: tuple[Host, ...] = field(default_factory=tuple)
