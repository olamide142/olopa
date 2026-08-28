"""Feed configuration for intel_sync.

Each entry describes one remote threat-intelligence list that gets downloaded
and materialized into a named set inside intel.json.

Set naming convention:
  org.threat_intel.<category>   — primary threat sets referenced by OIL rules
  org.allowlist.<category>      — known-good sets used for suppression
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


SetType = Literal["string", "ip", "domain", "hash"]


@dataclass(frozen=True)
class FeedSource:
    """One remote file that contributes entries to an intel set."""

    url: str
    # Expected line format: one entry per line, blank lines / '#' comments skipped.
    comment_prefix: str = "#"


@dataclass(frozen=True)
class IntelSetConfig:
    """Configuration for one named intel set."""

    name: str                         # OIL-visible set name (e.g. org.threat_intel.c2_domains)
    set_type: SetType                 # "string" | "ip" | "domain" | "hash"
    sources: list[FeedSource]
    description: str = ""
    # Maximum entries to retain (0 = unlimited).
    # Apply to the feeds that publish giant lists (500 K+ IPs).
    max_entries: int = 0


# Base URL template
_RAW = "https://raw.githubusercontent.com/romainmarcoux/{repo}/main/{file}"


INTEL_SETS: list[IntelSetConfig] = [
    # -- Outbound C2 / ransomware / phishing IPs (LAN → WAN direction) ---------
    IntelSetConfig(
        name="org.threat_intel.outgoing_ips",
        set_type="ip",
        description=(
            "C2 servers, ransomware infrastructure, and phishing endpoints "
            "(romainmarcoux/malicious-outgoing-ip). Use in network egress rules."
        ),
        sources=[
            FeedSource(url=_RAW.format(repo="malicious-outgoing-ip", file="full-outgoing-ip-aa.txt")),
            FeedSource(url=_RAW.format(repo="malicious-outgoing-ip", file="full-outgoing-ip-ab.txt")),
        ],
    ),

    # -- Inbound malicious IPs (WAN → LAN direction) ----------------------------
    IntelSetConfig(
        name="org.threat_intel.inbound_ips",
        set_type="ip",
        description=(
            "Inbound scanners, botnets, and attack infrastructure "
            "(romainmarcoux/malicious-ip). Top 40K list for inbound filtering."
        ),
        sources=[
            FeedSource(url=_RAW.format(repo="malicious-ip", file="full-40k.txt")),
        ],
        max_entries=40_000,
    ),

    # -- Phishing / C2 domains (DNS query matching) ----------------------------
    IntelSetConfig(
        name="org.threat_intel.c2_domains",
        set_type="domain",
        description=(
            "Malicious phishing and C2 callback domains "
            "(romainmarcoux/malicious-domains). Referenced by dns_detection.oil rules."
        ),
        sources=[
            FeedSource(url=_RAW.format(repo="malicious-domains", file="full-domains-aa.txt")),
            FeedSource(url=_RAW.format(repo="malicious-domains", file="full-domains-ab.txt")),
            FeedSource(url=_RAW.format(repo="malicious-domains", file="full-domains-ac.txt")),
        ],
    ),

    # -- Malware file hashes ----------------------------------------------------
    IntelSetConfig(
        name="org.threat_intel.malware_hashes",
        set_type="hash",
        description=(
            "Malware file hashes (MD5 + SHA256) from abuse.ch MalwareBazaar "
            "and OTX (romainmarcoux/malicious-hash)."
        ),
        sources=[
            FeedSource(url=_RAW.format(repo="malicious-hash", file="full-hash-sha256-aa.txt")),
            FeedSource(url=_RAW.format(repo="malicious-hash", file="full-hash-md5-aa.txt")),
        ],
    ),

    # -- Allowlist — known-good scanners / CDN IPs (suppression) ---------------
    IntelSetConfig(
        name="org.allowlist.known_scanners",
        set_type="ip",
        description=(
            "Legitimate scanners and infrastructure (Censys, UptimeRobot, "
            "Let's Encrypt) to suppress false positives in network rules."
        ),
        sources=[
            FeedSource(url=_RAW.format(repo="misc-ip-lists", file="ip-lists/censys")),
            FeedSource(url=_RAW.format(repo="misc-ip-lists", file="ip-lists/uptimerobot")),
            FeedSource(url=_RAW.format(repo="misc-ip-lists", file="ip-lists/letsencrypt")),
        ],
    ),
]


# -- Output configuration -------------------------------------------------------

import os as _os

def default_output_path() -> str:
    return _os.environ.get("OLOPA_INTEL_PATH", "/etc/olopa/intel.json")


def refresh_interval_s() -> int:
    """How often the sync loop re-fetches all feeds (default 3600 s = 1 h)."""
    raw = _os.environ.get("OLOPA_INTEL_REFRESH_S", "3600").strip()
    try:
        return max(60, int(raw))
    except ValueError:
        return 3600


def redis_url() -> str | None:
    """Redis target for IOC set distribution, or None to skip Redis entirely.

    Unset by default so a plain `python -m app.intel_sync.sync` run (e.g. in
    a dev shell with no Redis running) keeps working with just the intel.json
    file output.
    """
    raw = _os.environ.get("OLOPA_INTEL_REDIS_URL", "").strip()
    return raw or None
