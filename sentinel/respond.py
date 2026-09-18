"""Response actions.

Containment here is SIMULATED: blocking an IP writes it to a blocklist table
and an audit trail. Nothing touches a real firewall. The blocklist can be
exported as plain text, which is how a real firewall or proxy would consume
it, but wiring that up is a deliberate human decision.

Guardrail: automation must never be able to take down your own network, so
internal addresses and inventoried assets cannot be blocked from here.
"""
from __future__ import annotations

import ipaddress
from typing import Tuple

from .enrich import Enricher
from .storage import Storage


def contain_ip(storage: Storage, enricher: Enricher, ip: str, reason: str,
               actor: str = "analyst") -> Tuple[bool, str]:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False, "Not a valid IP address."
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return False, "Refusing to block a special-purpose address."
    if enricher.is_internal(ip) or enricher.asset_for(ip=ip):
        return False, ("Refusing to block an internal address. Isolate internal "
                       "hosts through the endpoint team, not the perimeter.")
    storage.block_ip(str(address), reason[:300], actor)
    return True, "Recorded %s on the blocklist (simulated containment)." % address
