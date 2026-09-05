"""Bind HTTP check-ins to the lane capability verified by CyberCore.

Caddy removes incoming X-Caldera-* headers and copies only the authorizer's
identity. This module does not accept an agent's claimed identity as authority.
"""
import re

PAW = re.compile(r"[a-f0-9]{24}")
GROUP = re.compile(r"lane-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")


async def authorized_beacon(profile, headers, find_link):
    paw = headers.get("X-Caldera-Paw", "")
    group = headers.get("X-Caldera-Group", "")
    if not PAW.fullmatch(paw) or not GROUP.fullmatch(group):
        return False
    if not isinstance(profile, dict) or profile.get("paw") != paw or profile.get("group") != group:
        return False
    results = profile.get("results", [])
    if not isinstance(results, list):
        return False
    # Upstream accepts result IDs independently of the reporting agent. Bind
    # each result to an existing link for this paw before any output is saved.
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("id"), str):
            return False
        link = await find_link(result["id"])
        if link is None or link.paw != paw:
            return False
    return True
