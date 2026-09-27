"""Build transparent discovery plans without executing Nmap."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveryPlan:
    """One explicit discovery action proposed for analyst review."""

    target: str
    profile: str
    purpose: str
    command: tuple[str, ...]


def build_baseline_discovery_plan(target: str) -> DiscoveryPlan:
    """Build the conservative baseline TCP service-discovery plan."""
    normalized_target = target.strip()
    if not normalized_target:
        raise ValueError("Discovery target must not be blank")

    return DiscoveryPlan(
        target=normalized_target,
        profile="baseline",
        purpose="discover open TCP services with version detection",
        command=("nmap", "-sV", "-oX", "-", normalized_target),
    )
