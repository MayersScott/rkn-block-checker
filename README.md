# RKN Block Checker

[![PyPI version](https://img.shields.io/pypi/v/rkn-block-checker.svg)](https://pypi.org/project/rkn-block-checker/)
[![CI](https://github.com/MayersScott/rkn-block-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/MayersScott/rkn-block-checker/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A small CLI that figures out whether the connection you're sitting on is in
an RKN/TSPU-blocked zone - and, more usefully, **what kind** of block it is
(DNS poisoning, TCP reset, TLS DPI on SNI, or an ISP stub page).

The point isn't "site X doesn't open." Browsers already tell you that. The
point is to look at each layer of the stack independently and report
*where* it broke. That tells you a lot more about your situation than a
generic "this site can't be reached" page.

## Quick start

```bash
pip install rkn-block-checker
rkn-check
```

That's it. The tool probes a built-in list of sites, classifies each
failure by layer, and prints a verdict. No config, no setup, nothing to
edit.

## Example output

```text
======================================================================
  RKN Block Checker
======================================================================
  IP:       95.165.xxx.xxx
  ISP:      AS12389 Rostelecom
  Location: Moscow, Moscow, RU
----------------------------------------------------------------------

Whitelist (should always work)
  name          verdict                    TCP     TLS     PLT  status
  --------------------------------------------------------------------
  gosuslugi     ✓ OK                      18ms    42ms   380ms  200
  yandex        ✓ OK                       8ms    25ms    95ms  200
  sberbank      ✓ OK                      12ms    38ms   250ms  200
  vk            ✓ OK                       9ms    28ms   180ms  200
  ...

Blacklist (RKN-restricted)
  name          verdict                    TCP     TLS     PLT  status
  --------------------------------------------------------------------
  instagram     ~ LIKELY TLS DPI          22ms       -       -  -
    └ TLS reset right after ClientHello - consistent with SNI-based DPI
  twitter/x     ~ LIKELY TLS DPI          24ms       -       -  -
    └ TLS handshake silently dropped - consistent with DPI filtering
  rutracker     ✗ HTTP STUB               18ms    45ms   120ms  200
    └ response body matches a known ISP stub-page marker
  protonvpn     ✗ DNS                        -       -       -  -
    └ system DNS doesn't resolve, DoH does - consistent with DNS poisoning

======================================================================
  Summary
----------------------------------------------------------------------
  Whitelist: 21/21 working
  Blacklist: 3/15 open, 12/15 blocked

  → Likely in an RKN-blocked zone (medium confidence).
    Most blacklist failures match censorship patterns (TLS DPI, TCP RST),
    but those signals can also be caused by server-side issues. A control
    vantage point would confirm.

  Block types in the blacklist:
    ~ LIKELY TLS DPI: 8
    ✗ DNS: 2
    ✗ HTTP STUB: 2
======================================================================
```

Verdict labels are **calibrated by confidence**: `✗` means a high-confidence
diagnosis (e.g. DNS poisoning confirmed by DoH, HTTP 451, a known stub-page
marker), `~ LIKELY` means a known censorship pattern matched but a single
signal can't rule out a server-side issue, and `?` means the symptom is
ambiguous. The summary line says so plainly - "high confidence", "medium
confidence", or "inconclusive" - and never claims more certainty than the
underlying signals support.

## Why this exists

If a site doesn't open, your browser tells you that. But if you want to
*do* something about it - pick the right circumvention tool, file a useful
bug report, or just understand what's happening to your traffic - you need
to know which part of the network stack is actually being interfered with.

Different censorship mechanisms leave different fingerprints:

- **DNS poisoning** is the cheapest and oldest. The ISP's resolver lies
  about a domain.
- **TCP reset** is IP-level blackholing. Rare in practice - most ISPs
  don't bother.
- **TLS DPI on SNI** is the modern TSPU/RKN signature. The middlebox
  watches for the SNI extension in the TLS ClientHello and tears the
  connection down once it sees a blocked hostname.
- **HTTP stub pages** are the polite kind: an ISP-controlled page served
  back with a "blocked by RKN" body, often with status 200 or the
  rarer-but-explicit 451.

`rkn-check` walks DNS → TCP → TLS → HTTP for each target and stops at the
first thing that fails. Whichever layer broke becomes the verdict.

## Common scenarios

### Just diagnose the connection you're on

```bash
rkn-check
```

Probes the built-in lists (~21 control sites, ~15 RKN-restricted), prints
a per-site report and a summary verdict.

### Check a single URL

```bash
rkn-check --url https://example.com
rkn-check --url example.com --url google.com    # repeat for several
```

Skips the built-in lists entirely and runs an ad-hoc check against just
the URLs you pass. No summary verdict - there's no control group to
compare against. Use this when you want to know "did *this one site* come
through?" without paying for a full scan.

### Pipe to `jq`

```bash
# names of every blocked site
rkn-check --json | jq -r '.blacklist[] | select(.verdict != "OK") | .name'

# count by block type
rkn-check --json | jq '.blacklist | group_by(.verdict)
                       | map({verdict: .[0].verdict, count: length})'

# only DPI-style blocks (TCP fine, TLS dies)
rkn-check --json | jq '.blacklist[] | select(.verdict == "TLS_BLOCK" and .tcp_ok)'
```

### Probing through a proxy

```bash
pip install 'rkn-block-checker[proxy]'

rkn-check --proxy socks5://192.168.2.11:1080
rkn-check --proxy socks5h://127.0.0.1:1080     # DNS resolved proxy-side
rkn-check --proxy http://user:pass@proxy.local:8080
```

Supported schemes: `socks5`, `socks5h`, `socks4`, `http`. A port is
mandatory. SOCKS support needs the `proxy` extra (PySocks); without it
the flag exits with an error rather than silently probing direct.

**The system DNS lookup is deliberately not proxied.** Its whole job is
to show what the *local* resolver claims, so it can be compared against
the DoH control - and that comparison is the only way to see ISP-level
DNS poisoning. Route both sides through the proxy and you lose the
signal. Everything else - TCP, TLS, HTTP, and the DoH lookup - goes
through the proxy.

This is the flag to reach for when you have a vantage point on a
different path (a router's SOCKS inbound, a VPS, a phone's hotspot) and
want to compare it against the connection you're sitting on.

### Use your own target lists

```bash
rkn-check --black-file my-list.txt
rkn-check --white-file my-control.json --black-file my-targets.json
```

See [Custom target lists](#custom-target-lists) below for the file format.

### Run from cron and store JSON over time

```bash
rkn-check --json --no-self-info > "snapshots/$(date -I).json"
```

`--no-self-info` skips the public-IP lookup so the tool doesn't hit
`ipinfo.io` on every cron tick (and so the resulting JSON doesn't carry
your IP).

## Usage

```text
rkn-check [-h] [--json] [--white] [--black]
          [--white-file PATH] [--black-file PATH] [--url URL]
          [--timeout TIMEOUT] [--workers WORKERS] [-v]
          [--no-self-info] [--identify] [--proxy URL]
```

| flag | what it does |
|------|--------------|
| `--json` | emit machine-readable JSON instead of the colored report |
| `--white` | check only the control (whitelist) targets |
| `--black` | check only the blacklist targets |
| `--white-file PATH` | replace the built-in whitelist with a `.txt` or `.json` file |
| `--black-file PATH` | replace the built-in blacklist with a `.txt` or `.json` file |
| `--url URL` | probe a single URL or hostname; repeat for several. Skips built-in lists |
| `--timeout T` | per-probe timeout in seconds (default 5.0) |
| `--workers N` | thread pool size for parallel checks (default 10) |
| `--no-self-info` | skip the public-IP lookup at the top of the report |
| `--identify` | send a self-identifying User-Agent instead of a generic Chrome one. See [Privacy](#privacy-and-threat-model) |
| `--proxy URL` | route the TCP/TLS/HTTP probes and the DoH control lookup through a proxy. See [Probing through a proxy](#probing-through-a-proxy) |
| `-v` / `-vv` | logging at INFO / DEBUG |

`--white` and `--black` are mutually exclusive. `--url` cannot be combined
with `--white`/`--black`/`--white-file`/`--black-file` - ad-hoc mode runs
only the URLs you pass.

## How it works

For each target the tool walks DNS → TCP → TLS → HTTP and stops at the
first thing that fails. Whichever layer broke becomes the verdict.

| layer | probe | what a failure means |
|------:|-------|----------------------|
| DNS  | system resolver vs Cloudflare DoH, full address sets compared | sets agree but the system fails alone → DNS poisoning. Disjoint sets → transparent rewriting |
| TCP  | plain TCP handshake on `:443` | a `RST` is IP-level blackholing. Rare - most ISPs don't bother |
| TLS  | TLS handshake with SNI = target host | reset/timeout *here*, with TCP working fine, is the classic TSPU/DPI signature: the middlebox sees the SNI and tears the connection down |
| HTTP | `GET` after handshake completes | 451, or an ISP stub page returning 200 with a "blocked by Roskomnadzor" body |

Alongside the verdict, each row carries the **country of the target's
IP** (the `GEO` column) - useful for spotting that a "working" site is
actually being served from somewhere unexpected. See
[Privacy](#privacy-and-threat-model) for what that lookup costs you.

Two probes are worth calling out:

**System DNS vs DoH, set-based.** The cheapest way to "block" a site is
to make the ISP's DNS lie. Every host is resolved twice - once via
`getaddrinfo` (which uses whatever resolver the OS is configured for,
usually the ISP's) and once via Cloudflare's DoH endpoint, which the ISP
can't intercept. The two **sets** of returned IPs are then compared:
disagreement only counts when the sets are **completely disjoint**. Any
shared address is treated as load balancing, not poisoning - large sites
typically rotate the order of multiple A-records on every query, and
comparing only the first IP from each side produces false positives on
every other run.

**TLS handshake with SNI.** Modern TSPU equipment doesn't drop the TCP
connection - it lets you connect, reads the SNI extension out of the
ClientHello, and *then* sends a RST or simply stops responding. So we
have to actually start the TLS handshake to see this. A `TLS_BLOCK` after
a clean `TCP_OK` is the unambiguous fingerprint of DPI-based blocking.

## Verdicts and confidence

Every result carries both a verdict and a confidence level. The verdict
says **what kind** of failure happened; the confidence says how
trustworthy the diagnosis is.

| verdict | meaning |
|---------|---------|
| `OK` | the site loaded normally |
| `DNS_BLOCK` | system DNS doesn't resolve while DoH does - consistent with poisoning |
| `TCP_RESET` | TCP handshake answered with RST |
| `TLS_BLOCK` | TCP succeeded but TLS handshake was reset, dropped, or otherwise killed (typical DPI on SNI) |
| `HTTP_STUB` | the response was a known ISP stub page or HTTP 451 |
| `TIMEOUT` | something timed out, not enough to classify further |
| `DOWN` | resolution and connectivity both failed in ways that aren't censorship-shaped |
| `UNKNOWN` | unexpected error, see notes |

Confidence levels:

- **HIGH** - two independent signals agree (e.g. DNS poisoning confirmed
  by DoH, an explicit HTTP 451, a known stub-page marker in the body).
- **MEDIUM** - a known censorship pattern matches, but the signal alone
  doesn't rule out a server-side issue or a flaky path (TLS reset right
  after ClientHello, TCP RST mid-stream).
- **LOW** - symptom is ambiguous (a generic timeout, an unclassified
  failure).

The summary line at the bottom mirrors this. With most blacklist failures
matching high-confidence patterns it says "Likely in an RKN-blocked zone
(high confidence)". If most signals are medium it lowers the claim. And
when the **whitelist** itself is mostly failing it doesn't claim either
way - without a working baseline you can't separate censorship from a
broken uplink, so the summary becomes "Inconclusive".

## Privacy and threat model

`rkn-check` is a diagnostic tool, not a circumvention tool. But the
people running it are typically already under network surveillance of
some kind, so the defaults are chosen to minimize the footprint a single
run leaves behind.

**User-Agent.** The default UA is a generic Chrome-on-Windows string with
the full set of browser-like headers (`Accept`, `Accept-Language`,
`Sec-Fetch-*`, etc.). The earlier `Mozilla/5.0 (RKN-Checker)` default was
unique enough to fingerprint a tool run in any logs along the path -
including, in some jurisdictions, VPN-provider logs that get handed to
regulators on request. A generic UA blends the request in with normal
traffic. If you *want* to be seen as diagnostic tooling - for example
when probing infrastructure you control - pass `--identify` to switch to
a self-identifying UA (`rkn-block-checker/<ver>`).

**Public-IP lookup.** By default the tool fetches your IP/ISP/location
from `ipinfo.io` and prints it at the top of the report. This is purely
for the human reading the report - the diagnosis itself doesn't depend
on it. Pass `--no-self-info` to skip that lookup entirely; that's also
the right thing to do in cron scripts and in CI.

**Target GeoIP.** To fill the `GEO` column the tool resolves each target
through the *system* resolver and POSTs the resulting IP list to
`ip-api.com` in one batch. Two caveats worth knowing: the request goes
over plain **HTTP** (that's what the free tier offers), and it is **not**
routed through `--proxy` - so with a proxy configured, the flag shown is
the country of whatever the local resolver returned, which is exactly the
answer you don't trust if DNS is being poisoned. The lookup is
best-effort: it has a 3s timeout and any failure just leaves the column
empty.

**No telemetry.** The tool doesn't phone home. The only outbound
connections are: the per-target probes you asked for, the DoH lookup to
`cloudflare-dns.com` (always on - it's the control side of the DNS
comparison), the `ip-api.com` GeoIP batch described above, and the
optional `ipinfo.io` lookup unless you disabled it.

**No exfil of probe results.** Results are printed to stdout. They go
nowhere else.

## JSON output

`--json` emits a single object containing `self_info` (the IP/ISP block
from the header, or `null` if `--no-self-info` is set) and the result
lists. Every result is the full per-target probe trace - which DNS
resolvers returned what, whether TCP and TLS succeeded with timings, the
HTTP status, the verdict, the confidence level, and human-readable notes.

A trimmed sample (full version: [`docs/sample-output.json`](docs/sample-output.json)):

```json
{
  "self_info": {
    "ip": "95.165.xxx.xxx",
    "city": "Moscow",
    "country": "RU",
    "org": "AS12389 Rostelecom"
  },
  "whitelist": [
    {
      "name": "gosuslugi",
      "url": "https://www.gosuslugi.ru/",
      "verdict": "OK",
      "confidence": "HIGH",
      "notes": [],
      "sys_ip": "95.181.182.36",
      "doh_ip": "95.181.182.36",
      "sys_ips": ["95.181.182.36"],
      "doh_ips": ["95.181.182.36"],
      "dns_mismatch": false,
      "tcp_ok": true,  "tcp_time_ms": 18.4,
      "tls_ok": true,  "tls_time_ms": 42.1,
      "tls_cert_cn": "*.gosuslugi.ru",
      "status_code": 200, "plt_ms": 380.7
    }
  ],
  "blacklist": [
    {
      "name": "instagram",
      "url": "https://www.instagram.com/",
      "verdict": "TLS_BLOCK",
      "confidence": "MEDIUM",
      "notes": ["TLS reset right after ClientHello - consistent with SNI-based DPI filtering"],
      "tcp_ok": true,  "tcp_time_ms": 22.4,
      "tls_ok": false, "tls_error": "connection reset during TLS"
    },
    {
      "name": "protonvpn",
      "url": "https://protonvpn.com/",
      "verdict": "DNS_BLOCK",
      "confidence": "HIGH",
      "notes": ["system DNS doesn't resolve, DoH does - consistent with DNS poisoning"],
      "sys_ip": null, "doh_ip": "185.70.40.182",
      "sys_ips": [], "doh_ips": ["185.70.40.182"],
      "dns_error": "system resolver failed, DoH succeeded",
      "tcp_ok": false
    }
  ]
}
```

`sys_ip` / `doh_ip` carry the lowest-sorted address from each set for
backward compatibility; `sys_ips` / `doh_ips` carry the full sorted
lists. The probe trace fields are always present so you can tell *why* a
verdict was reached - a `TLS_BLOCK` with `tcp_ok: true` is the DPI-on-SNI
signature; one with `tcp_ok: false` would mean something else failed
first.

## Custom target lists

`--white-file` and `--black-file` accept either JSON or plain text. The
format is picked by file extension (`.json` → JSON, anything else → text).

**JSON format** - a flat object mapping name to URL:

```json
{
  "google":   "https://google.com",
  "github":   "https://github.com",
  "rutracker": "https://rutracker.org"
}
```

**Text format** - one entry per line. Three forms are accepted:

```text
# bare URL - name auto-derived from the hostname
https://example.com

# name<whitespace>URL
github https://github.com

# name=URL
custom=https://example.org

# blank lines and #-comments are skipped
```

URLs without a scheme get `https://` prepended. Duplicate names overwrite
(with a warning logged); use unique names if both should be probed.

## Install

Python 3.10+.

From PyPI:

```bash
pip install rkn-block-checker
```

From source:

```bash
git clone https://github.com/MayersScott/rkn-block-checker.git
cd rkn-block-checker
pip install -e .
```

For development (adds pytest and friends):

```bash
pip install -e ".[dev]"
```

## Layout

```text
rkn_checker/
  __main__.py     # python -m rkn_checker
  cli.py          # argparse + entry point
  core.py         # orchestrates DNS -> TCP -> TLS -> HTTP
  dns.py          # system resolver + Cloudflare DoH (full address sets)
  network.py      # raw TCP and TLS probes
  http.py         # HTTP GET, header set, stub-page detection
  output.py       # colored CLI report
  lists.py        # parser for user-supplied target files
  targets.py      # built-in whitelist, blacklist, stub markers
  models.py       # CheckResult, Verdict, Confidence
tests/            # pytest, all network calls mocked
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

No network calls in the test suite - every probe is mocked, so it runs
the same in CI, on a plane, or behind a corporate proxy.

## Releasing

Releases are pushed to PyPI automatically by the `release.yml` workflow
when a `v*` tag is pushed. The workflow uses
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) - no
API token in repo secrets.

To ship a new version:

```bash
# bump version in pyproject.toml first, commit
git tag v0.3.4
git push origin v0.3.4
```

The workflow checks that the tag matches `pyproject.toml`'s version,
builds sdist + wheel, runs `twine check --strict`, publishes to PyPI,
and attaches the artifacts to a GitHub Release with auto-generated
notes.

## Caveats

- IPv4 only. Some Russian ISPs treat IPv6 differently (often less
  filtered) but the v4 path is what users actually experience in
  practice.
- The built-in target lists are small (~20 sites per category). That's
  enough for a verdict but won't catch a block that affects only one
  specific resource. Use `--url` for ad-hoc checks or `--white-file` /
  `--black-file` for your own lists.
- One-shot snapshot, no retries, no longitudinal tracking. If you want
  to monitor a connection over time, run `rkn-check --json` from cron
  and store the snapshots.
- Stub markers are mostly Russian-language phrases narrowed enough to
  avoid false positives on unrelated articles that happen to mention
  Roskomnadzor. New patterns get added when reported.

## Acknowledgements

This project was significantly improved by people who looked at the code
critically and reported issues with concrete reproductions. Listed in the
order their contributions landed:

- [@vladon](https://github.com/vladon) - security holes, misclassifications
  and edge case fixes ([#1](https://github.com/MayersScott/rkn-block-checker/pull/1)):
  silent DNS pipeline failures, TLS misclassifications, narrowed stub markers,
  validation, `--no-self-info` flag, and four new test files.
- [@easymoney322](https://github.com/easymoney322) - flagged the unique-UA
  fingerprinting risk
  ([#2](https://github.com/MayersScott/rkn-block-checker/issues/2)). The
  threat model around VPN-provider logs was the right one to raise; led to
  the generic Chrome UA default and the `--identify` opt-in.
- [@rlobanov](https://github.com/rlobanov) - pointed out that ad-hoc URL
  checking required editing source files
  ([#4](https://github.com/MayersScott/rkn-block-checker/issues/4)); led to
  the `--url` flag (repeatable) for one-shot probes without touching the
  built-in lists.
- [@AndreyKopeyko](https://github.com/AndreyKopeyko) - caught a real false
  positive in DNS rewriting detection on multi-A-record sites
  ([#5](https://github.com/MayersScott/rkn-block-checker/issues/5)). The
  reproduction with `host(1)` made the bug obvious; led to set-based DNS
  comparison that only flags rewriting when the address sets are completely
  disjoint.
- [@tagantank](https://github.com/tagantank) — Docker / Compose support
  ([#3](https://github.com/MayersScott/rkn-block-checker/pull/3)) so the
  tool can be run without touching the host's Python environment.

If you spot something off, open an issue with a reproduction - that's the
single most useful thing you can do.

## License

MIT.