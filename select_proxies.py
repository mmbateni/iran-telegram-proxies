#!/usr/bin/env python3
"""
select_proxies.py
-----------------
Fetch Telegram MTProto proxies from MahsaNetConfigTopic/proxy, check them,
and emit the best ~N using a two-stage strategy:
Stage 1 – Connectivity check
TCP-connect to every server:port with a short timeout.
Proxies that respond are marked "alive".
Stage 2 – Diversity-weighted selection
Cluster proxies by (secret_type × port_bucket × server_prefix).
Round-robin across clusters, always preferring alive proxies and,
among those, FakeTLS (ee…) > random-pad (dd…) > basic secret and
port 443 > 8443 > others.
This maximises the probability that at least one selected proxy
works for any given user inside Iran, even if an IP block or
port block is in place on a particular ISP.
Usage:
python select_proxies.py [--count N] [--timeout T] [--workers W]
[--out proxies.txt] [--html proxies.html]
[--no-check]
"""
from __future__ import annotations
import argparse
import concurrent.futures
import html as html_module
import re
import socket
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
SOURCE_URL = (
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/proxy/main/proxies.txt"
)
DEFAULT_COUNT   = 100
DEFAULT_TIMEOUT = 4    # seconds for TCP connect
DEFAULT_WORKERS = 200  # concurrent socket checkers

# ---------------------------------------------------------------------------
# Hostname validation
# ---------------------------------------------------------------------------
_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

def is_valid_hostname(host: str) -> bool:
    """Return True if *host* is a plausible IPv4, IPv6, or DNS name.

    Rejects anything Python's IDNA encoder would refuse (empty labels,
    labels > 63 chars, total name > 253 chars), which would cause
    socket.create_connection() to raise UnicodeError at check time.
    """
    # Plain IPv4  (e.g. 1.2.3.4)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return True
    # IPv6 — bracketed ([::1]) or bare (contains a colon)
    if host.startswith("[") or ":" in host:
        return True
    # DNS hostname
    name = host.rstrip(".")      # strip optional trailing dot (FQDN)
    if not name or len(name) > 253:
        return False
    for label in name.split("."):
        if not label or len(label) > 63 or not _LABEL_RE.match(label):
            return False
    return True

# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------
def fetch_lines(url: str) -> list[str]:
    """Download *url* and return non-empty, stripped lines."""
    with urlopen(url, timeout=20) as resp:
        return [
            line.strip()
            for line in resp.read().decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ]

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
_PROXY_RE = re.compile(
    r"(?:tg://proxy|https://t\.me/proxy)\?"
    r"(?:.*?&)?server=([^&\s)]+)&(?:.*?&)?port=(\d+)&(?:.*?&)?secret=([0-9a-fA-F+/=A-Za-z]{32,})",
    re.IGNORECASE,
)

def _make_clean_url(server: str, port: int, secret: str) -> str:
    """Reconstruct a clean, well-formed tg://proxy link."""
    return f"tg://proxy?server={server}&port={port}&secret={secret}"

def _make_tme_url(server: str, port: int, secret: str) -> str:
    """Return an https://t.me/proxy link.

    Uses standard HTTPS so it works in every browser regardless of whether
    Telegram has registered the tg:// URI handler on the device.
    """
    return f"https://t.me/proxy?server={server}&port={port}&secret={secret}"

def parse_proxy(line: str) -> dict | None:
    """
    Parse a tg://proxy?... or https://t.me/proxy?... line.
    Returns a dict with keys: raw (clean reconstructed URL), server, port, secret.
    """
    line = line.strip()
    m = _PROXY_RE.search(line)
    if m:
        try:
            server = m.group(1)
            port   = int(m.group(2))
            secret = m.group(3).lower()
            if not re.match(r"^[\w.\-:]{3,}$", server) or not is_valid_hostname(server):
                return None
            return {
                "raw":    _make_clean_url(server, port, secret),
                "server": server,
                "port":   port,
                "secret": secret,
            }
        except ValueError:
            pass

    if line.startswith("tg://"):
        clean = re.split(r"[\s)\]]", line)[0]
        line_norm = clean.replace("tg://proxy", "http://proxy", 1)
    elif line.startswith("https://t.me/proxy"):
        clean = re.split(r"[\s)\]]", line)[0]
        line_norm = clean
    else:
        return None

    try:
        qs = parse_qs(urlparse(line_norm).query)
        server = qs.get("server", [None])[0]
        port_s = qs.get("port",   [None])[0]
        secret = qs.get("secret", [None])[0]
        if not (server and port_s and secret):
            return None
        port   = int(port_s)
        secret = secret.lower()
        if not re.match(r"^[\w.\-:]{3,}$", server) or not is_valid_hostname(server):
            return None
        return {
            "raw":    _make_clean_url(server, port, secret),
            "server": server,
            "port":   port,
            "secret": secret,
        }
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Connectivity check
# ---------------------------------------------------------------------------
def check_tcp(proxy: dict, timeout: float) -> bool:
    """Return True if server:port accepts a TCP connection within *timeout* s."""
    try:
        with socket.create_connection((proxy["server"], proxy["port"]), timeout=timeout):
            return True
    except (OSError, UnicodeError):
        # OSError  — connection refused, timeout, network unreachable, etc.
        # UnicodeError — IDNA encoding fails for malformed hostnames that
        #                slipped through the parse-time validator (belt-and-
        #                suspenders guard; should not normally be reached).
        return False

def run_checks(proxies: list[dict], timeout: float, workers: int) -> None:
    """Populate proxy["alive"] for every proxy in-place (concurrent)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fmap = {ex.submit(check_tcp, p, timeout): p for p in proxies}
        done = 0
        for future in concurrent.futures.as_completed(fmap):
            p = fmap[future]
            p["alive"] = future.result()
            done += 1
            if done % 50 == 0 or done == len(proxies):
                alive_so_far = sum(1 for q in proxies if q.get("alive"))
                _log(f"  … {done}/{len(proxies)} checked, {alive_so_far} alive so far")

# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------
def secret_type(secret: str) -> str:
    s = secret.lower()
    if s.startswith("ee"):
        return "faketls"
    if s.startswith("dd"):
        return "dd"
    return "basic"

def port_bucket(port: int) -> str:
    if port == 443:
        return "443"
    if port in (80, 8080, 8443, 4433):
        return "alt"
    return "other"

def server_prefix(server: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", server):
        return ".".join(server.split(".")[:3])
    parts = server.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else server

def cluster_key(p: dict) -> str:
    return f"{secret_type(p['secret'])}|{port_bucket(p['port'])}|{server_prefix(p['server'])}"

_TYPE_RANK = {"faketls": 0, "dd": 1, "basic": 2}
_PORT_RANK = {443: 0, 8443: 1, 4433: 1, 80: 2, 8080: 2}

def priority_key(p: dict) -> tuple:
    alive_score = 0 if p.get("alive") else 1
    type_score  = _TYPE_RANK.get(secret_type(p["secret"]), 3)
    port_score  = _PORT_RANK.get(p["port"], 3)
    return (alive_score, type_score, port_score)

# ---------------------------------------------------------------------------
# Diversity-aware selection
# ---------------------------------------------------------------------------
def diverse_select(proxies: list[dict], n: int) -> list[dict]:
    clusters: dict[str, list[dict]] = defaultdict(list)
    for p in proxies:
        clusters[cluster_key(p)].append(p)
    for key in clusters:
        clusters[key].sort(key=priority_key)

    def cluster_rank(k: str) -> tuple:
        best = clusters[k][0]
        return (best.get("alive", False) is False, priority_key(best), k)

    bucket_order = sorted(clusters.keys(), key=cluster_rank)
    pointers  = {k: 0 for k in bucket_order}
    exhausted : set[str] = set()
    selected  : list[dict] = []

    while len(selected) < n and len(exhausted) < len(bucket_order):
        for key in bucket_order:
            if key in exhausted:
                continue
            idx = pointers[key]
            if idx >= len(clusters[key]):
                exhausted.add(key)
                continue
            selected.append(clusters[key][idx])
            pointers[key] += 1
            if len(selected) >= n:
                break
    return selected

# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
def write_txt(proxies: list[dict], path: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Telegram MTProto proxies — {len(proxies)} selected — {now}",
        f"# Source: https://github.com/MahsaNetConfigTopic/proxy",
        f"# Legend: ✅ alive (TCP responded)  ⚠ unverified (TCP timeout)",
        "",
    ]
    for p in proxies:
        tag   = "✅" if p.get("alive") else "⚠ "
        stype = secret_type(p["secret"])
        lines.append(f"# {tag} [{stype:8s}] port={p['port']:5d}  {p['server']}")
        lines.append(p["raw"])
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_html(proxies: list[dict], path: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for i, p in enumerate(proxies, 1):
        alive_badge = (
            '<span class="badge alive">✅ alive</span>'
            if p.get("alive")
            else '<span class="badge unverified">⚠ unverified</span>'
        )
        stype = secret_type(p["secret"])
        type_badge = f'<span class="badge type-{stype}">{stype}</span>'
        server_esc = html_module.escape(p["server"])
        raw_esc    = html_module.escape(p["raw"])
        tme_link   = html_module.escape(_make_tme_url(p["server"], p["port"], p["secret"]))
        rows.append(f"""
<tr>
<td class="num">{i}</td>
<td>{alive_badge} {type_badge}</td>
<td class="server">{server_esc}:{p['port']}</td>
<td class="actions">
<a href="{tme_link}" class="btn open" target="_blank" rel="noopener">Open in Telegram</a>
<button class="btn copy" onclick="copyText('{raw_esc}')">Copy link</button>
</td>
</tr>""")
    rows_html = "\n".join(rows)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Telegram MTProto Proxies — Iran</title>
<style>
:root {{
--bg: #0f1117; --surface: #1a1d27; --border: #2e3148;
--text: #e0e4f0; --muted: #7b82a0;
--alive: #22c55e; --unver: #f59e0b;
--faketls: #6366f1; --dd: #0ea5e9; --basic: #64748b;
--btn: #3b82f6;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
background: var(--bg); color: var(--text);
font-family: system-ui, sans-serif; font-size: 14px;
padding: 1.5rem;
}}
h1 {{ font-size: 1.4rem; margin-bottom: .3rem; }}
.meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }}
.meta a {{ color: var(--btn); }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: .55rem .75rem; border-bottom: 1px solid var(--border); text-align: left; }}
th {{ color: var(--muted); font-weight: 600; font-size: .8rem; text-transform: uppercase; }}
tr:hover {{ background: var(--surface); }}
.num {{ color: var(--muted); width: 2.5rem; }}
.server {{ font-family: monospace; }}
.badge {{
display: inline-block; font-size: .72rem; font-weight: 700;
padding: .15rem .45rem; border-radius: 4px; margin-right: .3rem;
}}
.alive     {{ background: #14532d; color: var(--alive); }}
.unverified{{ background: #451a03; color: var(--unver); }}
.type-faketls {{ background: #312e81; color: #a5b4fc; }}
.type-dd      {{ background: #0c4a6e; color: #7dd3fc; }}
.type-basic   {{ background: #1e293b; color: #94a3b8; }}
.actions {{ white-space: nowrap; }}
.btn {{
display: inline-block; padding: .3rem .75rem; border-radius: 6px;
font-size: .8rem; font-weight: 600; cursor: pointer;
text-decoration: none; border: none; margin-right: .4rem;
}}
.open {{ background: var(--btn); color: #fff; }}
.open:hover {{ background: #2563eb; }}
.copy {{ background: var(--surface); color: var(--text); border: 1px solid var(--border); }}
.copy:hover {{ background: var(--border); }}
#toast {{
position: fixed; bottom: 1.5rem; right: 1.5rem;
background: #22c55e; color: #fff; padding: .6rem 1.2rem;
border-radius: 8px; font-weight: 600; opacity: 0;
transition: opacity .3s; pointer-events: none;
}}
#toast.show {{ opacity: 1; }}
@media (max-width: 600px) {{
.server {{ display: none; }}
table {{ font-size: .78rem; }}
}}
</style>
</head>
<body>
<h1>📡 Telegram MTProto Proxies</h1>
<p class="meta">
{len(proxies)} proxies selected · Updated {now} ·
Source: <a href="https://github.com/MahsaNetConfigTopic/proxy">MahsaNetConfigTopic/proxy</a>
</p>
<table>
<thead>
<tr>
<th>#</th>
<th>Status / Type</th>
<th>Server</th>
<th>Actions</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
<div id="toast">Copied!</div>
<script>
function copyText(text) {{
navigator.clipboard.writeText(text).then(() => {{
const t = document.getElementById('toast');
t.classList.add('show');
setTimeout(() => t.classList.remove('show'), 1800);
}});
}}
</script>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------
def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Select the best diverse subset of Telegram MTProto proxies."
    )
    ap.add_argument("-n", "--count",   type=int,   default=DEFAULT_COUNT,
                    help=f"Number of proxies to select (default: {DEFAULT_COUNT})")
    ap.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"TCP connect timeout in seconds (default: {DEFAULT_TIMEOUT})")
    ap.add_argument("-w", "--workers", type=int,   default=DEFAULT_WORKERS,
                    help=f"Concurrent TCP checkers (default: {DEFAULT_WORKERS})")
    ap.add_argument("--source",        type=str,   default=SOURCE_URL,
                    help="URL of the raw proxy list")
    ap.add_argument("--out",           type=str,   default="output/proxies.txt",
                    help="Output text file path")
    ap.add_argument("--html",          type=str,   default="output/proxies.html",
                    help="Output HTML file path (set to '' to skip)")
    ap.add_argument("--no-check",      action="store_true",
                    help="Skip TCP checks (diversity-only mode)")
    args = ap.parse_args()

    _log(f"[1/4] Fetching proxy list from {args.source} …")
    lines = fetch_lines(args.source)
    _log(f"      {len(lines)} lines fetched")

    _log("[2/4] Parsing …")
    proxies: list[dict] = [p for line in lines if (p := parse_proxy(line))]
    
    seen: set[tuple] = set()
    unique: list[dict] = []
    for p in proxies:
        key = (p["server"].lower(), p["port"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    _log(f"      {len(unique)} unique proxies after deduplication")

    breakdown = defaultdict(int)
    for p in unique:
        breakdown[secret_type(p["secret"])] += 1
    _log(f"      types: {dict(breakdown)}")

    if args.no_check:
        _log("[3/4] Skipping TCP checks (--no-check)")
        for p in unique:
            p["alive"] = None
    else:
        _log(f"[3/4] Checking TCP connectivity "
             f"({args.workers} workers, {args.timeout}s timeout) …")
        run_checks(unique, args.timeout, args.workers)
        alive_count = sum(1 for p in unique if p.get("alive"))
        _log(f"      {alive_count}/{len(unique)} proxies alive")

    _log(f"[4/4] Selecting {args.count} proxies with diversity …")
    selected = diverse_select(unique, args.count)
    alive_sel = sum(1 for p in selected if p.get("alive"))
    _log(f"      selected {len(selected)}: "
         f"{alive_sel} alive, {len(selected)-alive_sel} diversity/unverified")
    
    sel_breakdown = defaultdict(int)
    for p in selected:
        sel_breakdown[secret_type(p["secret"])] += 1
    _log(f"      types in selection: {dict(sel_breakdown)}")

    if args.out:
        import os; os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        write_txt(selected, args.out)
        _log(f"      text  → {args.out}")
    if args.html:
        import os; os.makedirs(os.path.dirname(args.html) or ".", exist_ok=True)
        write_html(selected, args.html)
        _log(f"      html  → {args.html}")
    
    _log("Done ✓")

if __name__ == "__main__":
    main()
