from __future__ import annotations

import logging
import socket
import ssl
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0

def _open_socket(
    host: str,
    port: int,
    timeout: float,
    proxy_url: Optional[str] = None,
) -> socket.socket:
    """Open a connected TCP socket, going through a proxy if one is configured.

    Without a proxy, this is exactly socket.create_connection. With one, we
    route through PySocks (for SOCKS4/SOCKS5) or use HTTP CONNECT (for http://
    proxies) so that the same call site works in both cases. The reason we
    can't just patch the global default socket is that the DNS comparison
    needs to keep using the *system* resolver locally - only the per-target
    TCP/TLS probe should ride the proxy. Routing system DNS through a proxy
    would defeat the whole "is my ISP poisoning DNS" check
    """
    if not proxy_url:
        return socket.create_connection((host, port), timeout=timeout)

    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"socks5", "socks5h", "socks4", "http"}:
        raise ValueError(
            f"unsupported proxy scheme {scheme!r} - use socks5://, socks4://, or http://"
        )
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"proxy URL missing host or port: {proxy_url!r}")

    try:
        import socks  # type: ignore[import-untyped]
    except ImportError as e:
        raise RuntimeError(
            "proxy support requires PySocks. Install with: pip install 'rkn-block-checker[proxy]'"
        ) from e

    proxy_type = {
        "socks5": socks.SOCKS5,
        "socks5h": socks.SOCKS5,
        "socks4": socks.SOCKS4,
        "http": socks.HTTP,
    }[scheme]

    s = socks.socksocket()
    s.set_proxy(
        proxy_type,
        addr=parsed.hostname,
        port=parsed.port,
        username=parsed.username,
        password=parsed.password,
        rdns=(scheme == "socks5h"),
    )
    s.settimeout(timeout)
    s.connect((host, port))
    return s

def check_tcp(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> Tuple[bool, Optional[float], Optional[str]]:
    start = time.monotonic()
    try:
        sock = _open_socket(host, port, timeout, proxy_url=proxy_url)
        sock.close()
        return True, (time.monotonic() - start) * 1000, None
    except socket.timeout:
        return False, None, "timeout"
    except ConnectionResetError:
        return False, None, "connection reset"
    except OSError as e:
        return False, None, f"{type(e).__name__}: {e}"

def check_tls(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    proxy_url: Optional[str] = None,
) -> Tuple[bool, Optional[float], Optional[str], Optional[str]]:
    ctx = ssl.create_default_context()

    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    start = time.monotonic()
    try:
        sock = _open_socket(host, port, timeout, proxy_url=proxy_url)
        try:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cn = _extract_cn(ssock.getpeercert())
                return True, (time.monotonic() - start) * 1000, cn, None
        except BaseException:
            sock.close()
            raise
    except socket.timeout:
        return False, None, None, "timeout"
    except ssl.SSLError as e:
        return False, None, None, f"SSLError: {e.reason or e}"
    except ConnectionAbortedError:
        return False, None, None, "connection reset during TLS"
    except ConnectionResetError:
        return False, None, None, "connection reset during TLS"
    except OSError as e:
        return False, None, None, f"{type(e).__name__}: {e}"

def _extract_cn(cert: Optional[dict]) -> Optional[str]:
    if not cert:
        return None
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k == "commonName":
                return v
    return None
