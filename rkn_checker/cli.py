from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

import requests

from .core import check_url, get_self_info
from .lists import ListLoadError, load_targets
from .models import CheckResult
from .output import print_header, print_result, print_section, print_summary
from .targets import BLACK_URLS, WHITE_URLS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rkn-check",
        description=(
            "Probe a list of sites and decide whether the current network "
            "is in an RKN-blocked zone."
        ),
    )
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="emit machine-readable JSON instead of the colored report")
    p.add_argument("--white", dest="white_only", action="store_true",
                   help="check only the control (whitelist) targets")
    p.add_argument("--black", dest="black_only", action="store_true",
                   help="check only the blacklist targets")
    p.add_argument("--white-file", dest="white_file", metavar="PATH",
                   help="load whitelist targets from a .txt or .json file "
                        "(replaces the built-in whitelist)")
    p.add_argument("--black-file", dest="black_file", metavar="PATH",
                   help="load blacklist targets from a .txt or .json file "
                        "(replaces the built-in blacklist)")
    p.add_argument("--url", dest="urls", action="append", default=[],
                   metavar="URL",
                   help="probe a single URL or hostname; repeat to probe "
                        "multiple. Skips the built-in lists entirely; runs as "
                        "an ad-hoc check with no whitelist/blacklist semantics. "
                        "Conflicts with --white-file/--black-file.")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="per-probe timeout in seconds (default: 5.0)")
    p.add_argument("--workers", type=int, default=10,
                   help="thread pool size for parallel checks (default: 10)")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="increase log verbosity (-v info, -vv debug)")
    p.add_argument("--no-self-info", dest="no_self_info", action="store_true",
                   help="skip the external IP self-info lookup")
    p.add_argument("--identify", dest="identify", action="store_true",
                   help="send a self-identifying User-Agent ('rkn-block-checker/<ver>') "
                        "instead of a generic Chrome UA. Use this when probing "
                        "infrastructure you control or have permission to probe; "
                        "the default blends in with normal traffic to avoid "
                        "leaving a unique fingerprint in network logs.")
    p.add_argument("--proxy", dest="proxy_url", metavar="URL",
                   help="route per-target probes (TCP, TLS, HTTP, DoH) through "
                        "a proxy. Format: socks5://host:port, "
                        "socks5h://host:port (remote DNS), socks4://host:port, "
                        "or http://host:port. The local system DNS lookup is "
                        "intentionally NOT proxied — its purpose is to detect "
                        "ISP-level DNS poisoning, which requires going through "
                        "the local resolver. Authentication: include user:pass@.")
    return p


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _resolve_lists(
    white_file: str | None,
    black_file: str | None,
) -> tuple[dict[str, str], dict[str, str]]:
    white = WHITE_URLS
    black = BLACK_URLS
    if white_file:
        white = load_targets(white_file)
    if black_file:
        black = load_targets(black_file)
    return white, black


def _ad_hoc_targets(raw_urls: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in raw_urls:
        url = raw.strip()
        if not url:
            continue
        if "://" not in url:
            url = "https://" + url
        host = urlparse(url).hostname or url
        base_name = host.replace(".", "-")
        name = base_name
        n = 2
        while name in out:
            name = f"{base_name}-{n}"
            n += 1
        out[name] = url
    return out


def _fetch_geo_cache(targets: dict[str, str]) -> dict[str, str]:
    if not targets:
        return {}
    
    name_to_ip = {}
    for name, url in targets.items():
        host = urlparse(url).hostname or url
        try:
            ip = socket.gethostbyname(host)
            name_to_ip[name] = ip
        except Exception:
            continue
            
    unique_ips = list(set(name_to_ip.values()))
    if not unique_ips:
        return {}

    url = "http://ip-api.com/batch?fields=query,status,countryCode"
    try:
        response = requests.post(url, json=unique_ips[:100], timeout=3.0)
        if response.status_code == 200:
            ip_to_cc = {
                item['query']: item.get('countryCode', '')
                for item in response.json()
                if item.get('status') == 'success'
            }
            return {
                name: ip_to_cc[ip] 
                for name, ip in name_to_ip.items() 
                if ip in ip_to_cc
            }
    except Exception:
        pass
    return {}


def _run_streaming(
    run_white: bool,
    run_black: bool,
    white_urls: dict[str, str],
    black_urls: dict[str, str],
    workers: int,
    timeout: float,
    identify: bool = False,
    proxy_url: Optional[str] = None,
) -> tuple[list[CheckResult], list[CheckResult]]:
    white_results: list[CheckResult] = []
    black_results: list[CheckResult] = []

    all_targets = {}
    if run_white:
        all_targets.update(white_urls)
    if run_black:
        all_targets.update(black_urls)
    geo_cache = _fetch_geo_cache(all_targets)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        white_futs = {
            pool.submit(check_url, name, url, timeout, identify, proxy_url): name
            for name, url in (white_urls.items() if run_white else [])
        }
        black_futs = {
            pool.submit(check_url, name, url, timeout, identify, proxy_url): name
            for name, url in (black_urls.items() if run_black else [])
        }

        if run_white:
            print_section("Whitelist (should always work)")
            for fut in as_completed(white_futs):
                r = fut.result()
                white_results.append(r)
                print_result(r, country_code=geo_cache.get(r.name, ""))
                sys.stdout.flush()

        if run_black:
            print_section("Blacklist (RKN-restricted)")
            for fut in as_completed(black_futs):
                r = fut.result()
                black_results.append(r)
                print_result(r, country_code=geo_cache.get(r.name, ""))
                sys.stdout.flush()

    return white_results, black_results


def _run_ad_hoc(
    targets: dict[str, str],
    workers: int,
    timeout: float,
    identify: bool,
    proxy_url: Optional[str] = None,
) -> list[CheckResult]:
    """Probe an ad-hoc list of URLs in a single section, no white/black split."""
    results: list[CheckResult] = []
    print_section(f"Ad-hoc URLs ({len(targets)})")
    
    geo_cache = _fetch_geo_cache(targets)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(check_url, name, url, timeout, identify, proxy_url): name
            for name, url in targets.items()
        }
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            print_result(r, country_code=geo_cache.get(r.name, ""))
            sys.stdout.flush()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    if args.white_only and args.black_only:
        parser.error("--white and --black are mutually exclusive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if args.urls and (args.white_file or args.black_file
                      or args.white_only or args.black_only):
        parser.error(
            "--url cannot be combined with --white/--black/--white-file/--black-file; "
            "ad-hoc mode runs the listed URLs and nothing else"
        )
    if args.proxy_url:
        p = urlparse(args.proxy_url)
        if not p.scheme or not p.hostname:
            parser.error(
                "--proxy must be a full URL with scheme, e.g. "
                "socks5://192.168.1.1:1080 or http://proxy.local:8080"
            )
        if p.scheme.lower() not in {"socks5", "socks5h", "socks4", "http"}:
            parser.error(
                f"--proxy scheme {p.scheme!r} not supported "
                "(use socks5, socks5h, socks4, or http)"
            )
        if not p.port:
            parser.error(
                "--proxy URL must include a port, e.g. "
                f"{p.scheme}://{p.hostname}:1080"
            )
        try:
            import socks  # noqa: F401
        except ImportError:
            parser.error(
                "--proxy requires PySocks. "
                "Install with: pip install 'rkn-block-checker[proxy]'"
            )

    if args.urls:
        ad_hoc = _ad_hoc_targets(args.urls)
        if not ad_hoc:
            parser.error("no usable --url targets after parsing")

        if args.as_json:
            from .core import check_urls_parallel
            results = check_urls_parallel(
                ad_hoc, args.workers, args.timeout,
                identify=args.identify, proxy_url=args.proxy_url,
            )
            self_info = (
                get_self_info(timeout=args.timeout)
                if not args.no_self_info else None
            )
            payload = {
                "self_info": self_info,
                "ad_hoc": [r.to_dict() for r in results],
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0

        if not args.no_self_info:
            print_header(get_self_info(timeout=args.timeout))
        else:
            print_header({})
        sys.stdout.flush()
        _run_ad_hoc(ad_hoc, args.workers, args.timeout, args.identify,
                    proxy_url=args.proxy_url)
        return 0

    try:
        white_urls, black_urls = _resolve_lists(args.white_file, args.black_file)
    except ListLoadError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    run_white = not args.black_only
    run_black = not args.white_only

    if args.as_json:
        from .core import check_urls_parallel
        white_results = (
            check_urls_parallel(
                white_urls, args.workers, args.timeout,
                identify=args.identify, proxy_url=args.proxy_url,
            )
            if run_white else []
        )
        black_results = (
            check_urls_parallel(
                black_urls, args.workers, args.timeout,
                identify=args.identify, proxy_url=args.proxy_url,
            )
            if run_black else []
        )
        self_info = get_self_info(timeout=args.timeout) if not args.no_self_info else None
        payload = {
            "self_info": self_info,
            "whitelist": [r.to_dict() for r in white_results],
            "blacklist": [r.to_dict() for r in black_results],
        }
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    if not args.no_self_info:
        print_header(get_self_info(timeout=args.timeout))
    else:
        print_header({})
    sys.stdout.flush()

    white_results, black_results = _run_streaming(
        run_white, run_black, white_urls, black_urls,
        args.workers, args.timeout, args.identify,
        proxy_url=args.proxy_url,
    )

    if run_white and run_black:
        print_summary(white_results, black_results)

    return 0


if __name__ == "__main__":
    sys.exit(main())