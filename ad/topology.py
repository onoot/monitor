"""Instance topology and checker lifecycle model.

Derived from publicly released Altay checkers (AltayCTF-2018/2019) the engine
follows a fixed contract:

    ip = config.IP_PATTERN.format(team_number=team)
    creds = Credentials.objects(team=team).order_by('-round').first()

    check_index -> register/signup -> save_creds -> auth/signin
                -> functional operations
                -> put (write this round's flag)
                -> next round: check_old_flag (read previous round's flag)

Because the contract is stable we can reconstruct the expected traffic shape
for an unknown service and diff it against what was actually observed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IP_PATTERN_RE = re.compile(r"IP_PATTERN\s*=\s*[\"'](?P<p>[^\"']+)[\"']")
TEAM_NUM_RE = re.compile(r"team_number\s*=\s*\{team_number\}")


@dataclass(frozen=True)
class TeamInstance:
    team_number: int
    ip: str


@dataclass
class Topology:
    ip_pattern: str = ""
    team_ips: dict[int, str] = field(default_factory=dict)

    @property
    def inferred(self) -> bool:
        return bool(self.team_ips)

    def team_cidrs(self, limit: int = 64) -> list[str]:
        return [f"{self.team_ips[num]}/32" for num in sorted(self.team_ips)[:limit]]

    def overlaps_configured_team_networks(self, cidrs: list[str]) -> list[str]:
        """Warn when a configured team network contains an inferred team IP."""
        overlaps = []
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            for ip in self.team_ips.values():
                if ipaddress.ip_address(ip) in net:
                    overlaps.append(cidr)
                    break
        return overlaps


def infer_topology(source_texts: list[str]) -> Topology:
    """Recover IP_PATTERN and the checker's own address from source dumps."""
    pattern = ""
    for text in source_texts:
        match = IP_PATTERN_RE.search(text)
        if match:
            pattern = match.group("p")
            break

    topo = Topology(ip_pattern=pattern)
    if not pattern:
        return topo

    team_ips: dict[int, str] = {}
    # Bound the expansion: real deployments have at most a few dozen teams.
    for team in range(0, 64):
        try:
            ip = pattern.format(team_number=team)
            ipaddress.ip_address(ip)
        except (ValueError, IndexError, KeyError):
            break
        team_ips[team] = ip
    topo.team_ips = team_ips
    return topo


LIFECYCLE_PHASES: list[tuple[str, str, str]] = [
    ("index", "Service availability probe", "checker"),
    ("register", "Account / entity creation (flag is planted here or later)", "checker"),
    ("auth", "Login with previously stored credentials", "checker"),
    ("operate", "Normal functional read/write operations", "both"),
    ("put", "This round's flag written into the service", "checker"),
    ("get_old", "Previous round's flag read back", "checker"),
]


@dataclass(frozen=True)
class LifecyclePhase:
    key: str
    description: str
    expected_actor: str


def lifecycle() -> list[LifecyclePhase]:
    return [LifecyclePhase(*row) for row in LIFECYCLE_PHASES]