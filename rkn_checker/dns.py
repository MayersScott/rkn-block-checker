from __future__ import annotations

import json
import logging
import socket
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 5.0


def resolve_system_all(host: str) -> frozenset[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror as e:
        logger.debug("system DNS failed for %s: %s", host, e)
        return frozenset()
    # sockaddr is typed (str, int) for AF_INET; str() pins the element type
    return frozenset(str(info[4][0]) for info in infos)


def resolve_doh_all(
    host: str,
    timeout: float = DOH_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> frozenset[str]:
    """Return every IPv4 address Cloudflare's DoH endpoint returns for `host`.

    If a proxy is configured, the DoH lookup goes through it. The system
    resolver call (resolve_system_all) deliberately doesn't — we *want* to
    see what the local network claims for the hostname so we can compare
    against an unfiltered control. Routing both sides through the proxy
    would defeat the comparison.
    """
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    try:
        r = requests.get(
            DOH_ENDPOINT,
            params={"name": host, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
            proxies=proxies,
        )
        if not r.ok:
            return frozenset()
        ips: set[str] = set()
        for ans in r.json().get("Answer", ()):
            if ans.get("type") == 1:
                data = ans.get("data")
                if data:
                    ips.add(data)
        return frozenset(ips)
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.debug("DoH failed for %s: %s", host, e)
        return frozenset()


def resolve_system(host: str) -> Optional[str]:
    ips = resolve_system_all(host)
    if not ips:
        return None
    return sorted(ips)[0]


def resolve_doh(
    host: str,
    timeout: float = DOH_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> Optional[str]:
    ips = resolve_doh_all(host, timeout=timeout, proxy_url=proxy_url)
    if not ips:
        return None
    return sorted(ips)[0]
