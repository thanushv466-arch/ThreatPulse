"""Enrichment: add context to an alert so an analyst can decide faster.

  * Threat intelligence: is this IP on our list of known-bad indicators?
  * Asset inventory:     how important is the machine that was targeted?
  * Network position:    is the address inside our network or outside?
"""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# NOTE: Python's ip.is_private is True for the RFC 5737 documentation ranges
# (203.0.113.0/24 etc.) used as "attackers" in the sample data, so we define
# "internal" explicitly instead of trusting is_private.
DEFAULT_INTERNAL = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


class Enricher:
    def __init__(self, intel_csv: Path, assets_yml: Path,
                 internal_networks: Optional[List[str]] = None):
        self.internal = [ipaddress.ip_network(n)
                         for n in (internal_networks or DEFAULT_INTERNAL)]
        self.intel: Dict[str, Dict[str, str]] = {}
        if intel_csv.exists():
            with open(intel_csv, newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    self.intel[row["indicator"].strip()] = row
        self.assets: Dict[str, Dict[str, Any]] = {}
        if assets_yml.exists():
            with open(assets_yml, encoding="utf-8") as handle:
                self.assets = (yaml.safe_load(handle) or {}).get("assets", {})
        self._by_ip = {a["ip"]: dict(a, hostname=h)
                       for h, a in self.assets.items() if a.get("ip")}

    def is_internal(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.internal)

    def intel_for(self, ip: Optional[str]) -> Optional[Dict[str, str]]:
        return self.intel.get(ip) if ip else None

    def asset_for(self, host: Optional[str] = None, ip: Optional[str] = None):
        if host and host in self.assets:
            return dict(self.assets[host], hostname=host)
        if ip and ip in self._by_ip:
            return self._by_ip[ip]
        return None

    def tag_event(self, event) -> None:
        """Stamp fields onto an event so rules can use them."""
        event.extra["src_internal"] = self.is_internal(event.src_ip)
        event.extra["dst_internal"] = self.is_internal(event.dst_ip)
        event.extra["dst_intel"] = self.intel_for(event.dst_ip) is not None
        event.extra["src_intel"] = self.intel_for(event.src_ip) is not None

    def context(self, src_ip, dst_ips, host) -> Dict[str, Any]:
        hits = []
        for ip in [src_ip] + list(dst_ips):
            intel = self.intel_for(ip)
            if intel and intel not in hits:
                hits.append(intel)
        asset = self.asset_for(host=host) or self.asset_for(ip=src_ip)
        return {
            "threat_intel": hits,
            "asset": asset,
            "src_internal": self.is_internal(src_ip),
        }
