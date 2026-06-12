📡 Iran Telegram Proxy Selector

A GitHub repository that automatically fetches the full Telegram MTProto proxy list
maintained by [MahsaNetConfigTopic/proxy](https://github.com/MahsaNetConfigTopic/proxy),
checks and filters them, and publishes a curated list of ≤ 100 proxies every 24 hours.

The selection strategy maximises the probability that at least one proxy works
for any given user inside Iran, regardless of which ISP they use or which IPs/ports
their ISP currently blocks.

## Quick start for users

**One-tap (phone)**
Open `[output/proxies.html](output/proxies.html)` in your phone browser
and tap **Open in Telegram** next to any proxy.

**One-tap (copy link)**
Open `[output/proxies.txt](output/proxies.txt)`, copy any `tg://proxy?…` line,
then paste it into your browser's address bar while Telegram is installed.

**Manual setup**
Go to Telegram → Settings → Data and Storage → Proxy → Add Proxy → MTProto
and enter the Server, Port, and Secret values from any entry.

## How proxies are selected

### Stage 1 — Connectivity check
`select_proxies.py` attempts a TCP handshake to every proxy's `server:port`
using a 4-second timeout, running 200 concurrent checks.
- A ✅ **alive** proxy responded to the TCP connection — the server is up.
- A ⚠ **unverified** proxy timed out — it may be down, or firewalled from GitHub's
  network but still reachable from Iran (hence not discarded entirely).

*Note: the check is done from GitHub Actions servers outside Iran. A proxy that passes the TCP check is almost certainly working; a proxy that fails might still work from inside Iran if the IP is only reachable from certain regions. This is why diversity-only proxies are kept.*

### Stage 2 — Diversity-aware selection
Proxies are grouped into clusters based on three dimensions:

| Dimension | Buckets |
| --- | --- |
| Secret type | `faketls` (ee…) · `dd` (random padding) · `basic` |
| Port | `443` · `alt` (80 / 8080 / 8443) · `other` |
| Server prefix | first `/24` for IPs · last two labels for hostnames |

Selection proceeds by round-robin across clusters: one proxy is picked
from each cluster in turn until the target count is reached.
Within each cluster the ranking is:
1. **Alive** (TCP responded) before unverified
2. **FakeTLS** (`ee…`) > random-padding (`dd…`) > basic
   *(FakeTLS disguises Telegram traffic as ordinary HTTPS, making it the hardest type to block by DPI).*
3. **Port 443** > 8443/8080 > other
   *(Port 443 is the least likely to be blocked wholesale).*

The combined effect is that the 100 selected proxies span as many different
servers, port groups, and secret types as possible, so a single ISP-level
block can only knock out a fraction of them.

## Running locally

No dependencies beyond the Python standard library (Python ≥ 3.10).

```bash
# Clone this repo
git clone https://github.com/YOUR_USERNAME/iran-tg-proxies
cd iran-tg-proxies

# Select 100 proxies with live checks
python select_proxies.py

# Select 50 without connectivity check (faster, diversity-only)
python select_proxies.py --count 50 --no-check

# Custom output paths
python select_proxies.py --out my_proxies.txt --html my_proxies.html

# All options
python select_proxies.py --help