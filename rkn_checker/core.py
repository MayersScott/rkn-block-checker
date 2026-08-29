from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator, Optional
from urllib.parse import urlparse

import requests

from . import dns as dns_mod
from . import http as http_mod
from . import network
from .models import CheckResult, Confidence, Verdict

logger = logging.getLogger(__name__)

DEFAULT_WORKERS = 10


def get_self_info(timeout: float = 5.0) -> dict:
    try:
        r = requests.get("https://ipinfo.io/json", timeout=timeout)
        if r.ok:
            return r.json()
    except requests.RequestException as e:
        logger.debug("self-info lookup failed: %s", e)
    return {}


def check_url(
    name: str,
    url: str,
    timeout: float = 5.0,
    identify: bool = False,
    proxy_url: Optional[str] = None,
) -> CheckResult:
    host = urlparse(url).hostname or url
    res = CheckResult(name=name, url=url)

    sys_ips = dns_mod.resolve_system_all(host)
    doh_ips = dns_mod.resolve_doh_all(host, timeout=timeout, proxy_url=proxy_url)

    res.sys_ips = sorted(sys_ips)
    res.doh_ips = sorted(doh_ips)
    res.sys_ip = res.sys_ips[0] if res.sys_ips else None
    res.doh_ip = res.doh_ips[0] if res.doh_ips else None

    if not sys_ips and doh_ips:
        res.verdict = Verdict.DNS_BLOCK
        res.confidence = Confidence.HIGH
        res.dns_error = "system resolver failed, DoH succeeded"
        res.notes.append(
            "system DNS doesn't resolve, DoH does - consistent with DNS poisoning"
        )
        return res

    if not sys_ips and not doh_ips:
        res.verdict = Verdict.DOWN
        res.confidence = Confidence.LOW
        res.dns_error = "domain not resolved anywhere"
        res.notes.append(
            "domain doesn't resolve via system DNS or DoH - could be NXDOMAIN, "
            "downed authoritative server, or DNS-level block"
        )
        return res

    if sys_ips and doh_ips and sys_ips.isdisjoint(doh_ips):
        res.dns_mismatch = True
        res.notes.append(
            f"DNS mismatch: sys={sorted(sys_ips)} vs doh={sorted(doh_ips)} "
            "(disjoint address sets - may indicate transparent DNS rewriting)"
        )

    if sys_ips and not doh_ips:
        res.notes.append(
            "DoH lookup failed - control comparison unavailable, "
            "DNS poisoning cannot be ruled out"
        )

    res.tcp_ok, res.tcp_time_ms, res.tcp_error = network.check_tcp(
        host, timeout=timeout, proxy_url=proxy_url
    )
    
    if not res.tcp_ok:
        if res.tcp_error == "timeout":
            res.verdict = Verdict.TIMEOUT
            res.confidence = Confidence.LOW
            res.notes.append(
                "TCP timeout on port 443 - could be IP block, route loss, "
                "or upstream congestion"
            )
        elif "reset" in (res.tcp_error or ""):
            res.verdict = Verdict.TCP_RESET
            res.confidence = Confidence.MEDIUM
            res.notes.append(
                "TCP RST received - pattern matches RST injection by a "
                "middlebox, but a busy server can also send RST"
            )
        else:
            res.verdict = Verdict.DOWN
            res.confidence = Confidence.LOW
            res.notes.append(f"TCP failed: {res.tcp_error}")
        return res

    (res.tls_ok, res.tls_time_ms, res.tls_cert_cn, res.tls_error) = network.check_tls(
        host, timeout=timeout, proxy_url=proxy_url
    )

    if not res.tls_ok:
        err = (res.tls_error or "").lower()
        if "reset" in err:
            res.verdict = Verdict.TLS_BLOCK
            res.confidence = Confidence.MEDIUM
            res.notes.append(
                "TLS reset right after ClientHello - consistent with SNI-based "
                "DPI filtering (typical TSPU/RKN signature), not proof"
            )
        elif "timeout" in err:
            res.verdict = Verdict.TLS_BLOCK
            res.confidence = Confidence.MEDIUM
            res.notes.append(
                "TLS handshake silently dropped - consistent with DPI filtering "
                "by ClientHello, but could be a flaky path"
            )
        else:
            res.verdict = Verdict.TLS_BLOCK
            res.confidence = Confidence.LOW
            res.notes.append(f"TLS error: {res.tls_error}")
        return res

    probe = http_mod.fetch(url, timeout=timeout, identify=identify, proxy_url=proxy_url)
    res.status_code = probe.status_code
    res.plt_ms = probe.elapsed_ms
    res.http_error = probe.error

    if probe.timed_out:
        res.verdict = Verdict.TIMEOUT
        res.confidence = Confidence.LOW
        return res
    if probe.error:
        res.verdict = Verdict.DOWN
        res.confidence = Confidence.LOW
        return res

    if res.status_code == 451:
        res.verdict = Verdict.HTTP_STUB
        res.confidence = Confidence.HIGH
        res.notes.append("HTTP 451 - Unavailable For Legal Reasons (explicit)")
        return res

    if http_mod.looks_like_stub(probe.body_snippet):
        res.verdict = Verdict.HTTP_STUB
        res.confidence = Confidence.HIGH
        res.notes.append(
            "response body matches a known ISP stub-page marker"
        )
        return res

    res.verdict = Verdict.OK
    res.confidence = Confidence.MEDIUM if res.dns_mismatch else Confidence.HIGH
    return res


def iter_check_urls(
    urls: dict[str, str],
    max_workers: int = DEFAULT_WORKERS,
    timeout: float = 5.0,
    identify: bool = False,
    proxy_url: Optional[str] = None,
) -> Iterator[CheckResult]:
    """Yield CheckResult objects as soon as each probe finishes."""
    if not urls:
        return
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures_map: dict = {}
        for name, url in urls.items():
            fut = pool.submit(check_url, name, url, timeout, identify, proxy_url)
            futures_map[fut] = name
        for fut in as_completed(futures_map):
            try:
                yield fut.result()
            except Exception as e:
                name = futures_map[fut]
                logger.exception("unexpected error probing %s", name)
                yield CheckResult(
                    name=name, url="?", verdict=Verdict.UNKNOWN,
                    notes=[f"unexpected error: {e}"],
                )


def check_urls_parallel(
    urls: dict[str, str],
    max_workers: int = DEFAULT_WORKERS,
    timeout: float = 5.0,
    identify: bool = False,
    proxy_url: Optional[str] = None,
) -> list[CheckResult]:
    name_order = list(urls.keys())
    by_name = {
        r.name: r
        for r in iter_check_urls(
            urls, max_workers=max_workers, timeout=timeout,
            identify=identify, proxy_url=proxy_url,
        )
    }
    return [by_name[name] for name in name_order if name in by_name]