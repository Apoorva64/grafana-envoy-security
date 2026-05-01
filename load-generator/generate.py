"""
Load generator for the Envoy security dashboard.

Generates realistic mixed traffic — normal requests, error-triggering paths,
5xx responses, upstream failures, timeouts, suspicious user agents, and
different HTTP methods — so the security panels in Grafana have interesting
data to display right away.
"""

import os
import random
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
TARGET_URL = os.getenv("TARGET_URL", "http://envoy:10000").rstrip("/")
RPS = float(os.getenv("REQUESTS_PER_SECOND", "500"))
WORKERS = int(os.getenv("WORKERS", "60"))


# ── Traffic profiles ──────────────────────────────────────────────────────────


@dataclass
class RequestSpec:
    """Describes a single HTTP request to send."""

    method: str = "GET"
    path: str = "/"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    weight: int = 10  # relative probability weight


# Normal browser traffic
NORMAL_PATHS = ["/", "/health", "/api/v1/users", "/api/v1/products", "/api/v1/orders",
                "/about", "/contact", "/login", "/dashboard", "/static/app.js"]

# Paths typical of automated reconnaissance / vulnerability scanning
RECON_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-login.php",
    "/admin", "/admin/login", "/phpmyadmin/", "/.htaccess",
    "/etc/passwd", "/api/v1/../../etc/passwd",
    "/actuator/env", "/actuator/health",
    "/.well-known/security.txt", "/robots.txt",
    "/server-status", "/.DS_Store",
    "/config.json", "/credentials.json",
    "/api/swagger.json", "/openapi.json",
]

# Paths that Envoy intentionally answers with direct 404 responses so the
# dashboard has realistic not-found/error traffic to analyze.
NOT_FOUND_PATHS = [
    "/missing",
    "/missing/favicon.ico",
    "/missing/app.bundle.js",
    "/not-found",
    "/not-found/profile",
    "/old-api/v1/users",
    "/old-api/v2/orders",
    "/deleted/page.html",
    "/deleted/assets/logo.png",
]

# Paths that Envoy intentionally answers with 5xx direct responses.
SERVER_ERROR_PATHS = [
    "/server-error",
    "/server-error/api/v1/users",
    "/server-error/api/v1/orders",
    "/bad-gateway",
    "/bad-gateway/api/v1/products",
    "/unavailable",
    "/unavailable/search",
    "/gateway-timeout",
    "/gateway-timeout/report",
]

# Paths that trigger real Envoy upstream errors instead of direct responses.
# /slow routes to a backend that sleeps longer than the route timeout, producing
# 504s with timeout flags. /upstream-unavailable routes to a closed backend port,
# producing 503 upstream failure signals.
UPSTREAM_PROBLEM_PATHS = [
    "/slow",
    "/slow/api/v1/report",
    "/slow/export.csv",
    "/slow/dashboard",
    "/upstream-unavailable",
    "/upstream-unavailable/api/v1/users",
    "/upstream-unavailable/health",
]

# User agents used by security scanners / exploit tools
SCANNER_AGENTS = [
    "sqlmap/1.7 (https://sqlmap.org)",
    "Nikto/2.1.6",
    "masscan/1.3",
    "Mozilla/5.0 (compatible; DirBuster-1.0)",
    "WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)",
    "Python/3.x httpx/0.24",
    "Go-http-client/1.1",
    "Nuclei - Open-source vulnerability scanner",
    "ffuf/2.1.0",
    "ZGrab/0.x",
    "curl/8.2.1",
    "Hydra",
    "wfuzz/3.1.0",
]

# Normal browser agents
BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

# Simulated client IPs (via X-Forwarded-For) representing real public address
# ranges from every inhabited continent.  Each tuple is (ip, weight) where
# weight reflects roughly how much web traffic that region generates — so the
# geographic heatmap in Grafana looks plausible rather than uniform.
#
# IPs are real routable addresses taken from well-known public ranges; no
# private / RFC-5737 documentation blocks are used so GeoIP lookup resolves.
SIMULATED_IPS_WEIGHTED: list[tuple[str, int]] = [
    # ── North America ────────────────────────────────────────────────────────
    # United States (high volume)
    ("8.8.8.8",        20),  # Google DNS, Mountain View CA
    ("8.8.4.4",        15),  # Google DNS (secondary)
    ("4.2.2.1",        12),  # Level3, US
    ("4.2.2.2",        12),
    ("23.185.0.1",     10),  # Fastly CDN edge
    ("104.16.0.1",     10),  # Cloudflare, US
    ("198.41.0.4",      8),  # Verisign, US
    ("199.7.91.13",     8),  # ICANN
    ("64.233.160.0",   10),  # Google, US
    ("45.33.32.156",    6),  # Linode (attacker VPS, US)
    # Canada
    ("99.79.49.1",      5),  # AWS Canada East
    ("206.167.0.1",     4),  # Shaw, Calgary
    # Mexico
    ("187.174.0.1",     4),  # Telmex, Mexico City
    ("189.196.0.1",     3),  # Axtel, Mexico

    # ── Europe ───────────────────────────────────────────────────────────────
    # Germany
    ("217.0.0.1",      12),  # Deutsche Telekom
    ("80.237.0.1",      8),  # Vodafone DE
    ("85.214.0.1",      6),  # Strato AG, Berlin (VPS)
    ("46.4.0.1",        8),  # Hetzner, Nuremberg (popular attack source)
    ("144.76.0.1",      6),  # Hetzner
    # France
    ("90.0.0.1",        8),  # Orange France
    ("212.27.0.1",      6),  # Proxad/Free SAS
    ("51.77.0.1",       5),  # OVH, Gravelines
    # United Kingdom
    ("81.2.69.0",       8),  # BT
    ("195.238.0.1",     6),  # Virgin Media
    ("51.148.0.1",      5),  # Microsoft Azure UK South
    # Netherlands
    ("80.101.0.1",      7),  # KPN
    ("185.220.101.1",   5),  # Tor exit node range (interesting for security)
    ("194.165.0.1",     4),  # Leaseweb, Amsterdam
    # Russia
    ("91.108.4.1",      8),  # Telegram (known source of bot traffic)
    ("5.188.0.1",       6),  # Yandex Cloud
    ("176.74.0.1",      5),  # Petersburg Internet Network
    ("185.234.218.1",   4),  # Serverius (scanner-heavy range)
    # Poland
    ("31.0.0.1",        4),  # Polkomtel
    # Sweden
    ("195.67.0.1",      3),  # Tele2 Sweden
    # Spain
    ("80.58.0.1",       5),  # Telefonica España
    ("195.55.0.1",      3),  # Vodafone ES
    # Italy
    ("62.101.0.1",      4),  # Telecom Italia
    # Ukraine
    ("46.162.0.1",      4),  # Kyivstar
    ("91.206.0.1",      3),  # DataHata, Kyiv

    # ── Asia-Pacific ─────────────────────────────────────────────────────────
    # China (high volume, mixed legit/bot)
    ("1.180.0.1",      16),  # China Telecom
    ("58.14.0.1",      14),  # China Unicom
    ("120.192.0.1",    10),  # China Mobile
    ("61.135.169.121",  8),  # Baidu crawler
    ("202.96.0.1",      6),  # China Telecom
    ("14.215.0.1",      6),  # Tencent
    # India
    ("1.6.0.1",        12),  # BSNL India
    ("117.195.0.1",     8),  # Airtel India
    ("59.144.0.1",      6),  # VSNL (Tata)
    ("103.21.0.1",      5),  # Cloudflare India PoP
    # Japan
    ("203.104.0.1",     8),  # NTT Communications
    ("126.0.0.1",       7),  # SoftBank BB
    ("220.110.0.1",     5),  # KDDI
    # South Korea
    ("1.246.0.1",       7),  # SK Telecom
    ("175.213.0.1",     5),  # LG Uplus
    # Australia
    ("1.128.0.1",       7),  # Telstra
    ("121.200.0.1",     4),  # Optus
    ("203.0.0.1",       3),  # AAPT, Australia
    # Singapore
    ("175.41.128.1",    6),  # AWS APac
    ("202.166.0.1",     4),  # Singtel
    # Indonesia
    ("114.122.0.1",     5),  # Telkomsel
    ("36.69.0.1",       4),  # Telkom Indonesia
    # Vietnam
    ("14.161.0.1",      4),  # VNPT
    # Hong Kong
    ("203.80.0.1",      4),  # HKT
    # Taiwan
    ("168.95.0.1",      4),  # Chunghwa Telecom
    # Pakistan
    ("114.42.0.1",      3),  # PTCL
    # Bangladesh
    ("103.152.0.1",     2),  # Grameenphone

    # ── Middle East ──────────────────────────────────────────────────────────
    # Turkey
    ("78.162.0.1",      5),  # Turk Telekom
    # Saudi Arabia
    ("37.0.0.1",        4),  # STC
    ("212.14.0.1",      3),  # Mobily
    # UAE
    ("185.93.0.1",      3),  # du Telecom
    # Israel
    ("82.80.0.1",       3),  # Partner Communications
    # Iran
    ("94.74.0.1",       3),  # Shatel, Tehran

    # ── Africa ───────────────────────────────────────────────────────────────
    # Nigeria (largest internet market)
    ("197.210.0.1",     5),  # MTN Nigeria
    ("41.206.0.1",      3),  # Spectranet
    # South Africa
    ("196.25.0.1",      4),  # Telkom SA
    ("105.0.0.1",       3),  # Vodacom SA
    # Egypt
    ("197.32.0.1",      3),  # TE Data
    # Kenya
    ("196.200.0.1",     2),  # Safaricom
    # Ethiopia
    ("196.188.0.1",     2),  # Ethio Telecom

    # ── Latin America ────────────────────────────────────────────────────────
    # Brazil (biggest)
    ("189.1.0.1",       9),  # Claro Brasil
    ("177.0.0.1",       8),  # NET/Claro
    ("200.152.0.1",     6),  # GVT / Vivo
    ("179.108.0.1",     5),  # Oi Telecom
    # Argentina
    ("190.0.0.1",       5),  # Telecom Argentina
    ("200.49.0.1",      3),  # Fibertel
    # Colombia
    ("190.242.0.1",     3),  # ETB
    ("181.65.0.1",      2),  # Claro Colombia
    # Chile
    ("200.75.0.1",      3),  # Entel Chile

    # ── Known attack / scan infrastructure ──────────────────────────────────
    # Shodan scanner nodes
    ("198.20.69.74",    4),
    ("198.20.70.114",   4),
    ("198.20.99.130",   4),
    # Censys nodes
    ("162.142.125.1",   3),
    ("167.94.138.1",    3),
    # Common "bulletproof" hosting widely seen in attack logs
    ("193.32.162.1",    3),  # Selectel, Russia
    ("185.220.100.1",   3),  # Tor exit, Netherlands
    ("89.234.157.254",  2),  # Tor / FDN, France
]

# Flat list of IPs (expanded by weight) for O(1) random.choice
SIMULATED_IPS: list[str] = [
    ip for ip, w in SIMULATED_IPS_WEIGHTED for _ in range(w)
]

# HTTP methods to sprinkle into the traffic mix
EXTRA_METHODS = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# ── Cardinality-test helpers ───────────────────────────────────────────────────

_UA_PRODUCTS = [
    "Mozilla/5.0", "curl", "python-requests", "axios", "okhttp", "Go-http-client",
    "Java/HttpClient", "Dalvik", "libwww-perl", "wget", "HTTPie", "Scrapy",
]
_UA_OS = [
    "(Windows NT 10.0; Win64; x64)", "(Macintosh; Intel Mac OS X 14_6)",
    "(X11; Linux x86_64)", "(Android 14; Pixel 8)", "(iPhone; CPU iPhone OS 17_5)",
    "(compatible; Bot/1.0)", "(Linux; arm64)", "(FreeBSD; amd64)",
]
_UA_ENGINES = [
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36",
    "Gecko/20100101 Firefox/{v}",
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} Safari/605.1.15",
    "rv:{v}",
    "",
]
_UA_TOOLS = [
    "scanner/{v}", "bot/{v}", "crawler/{v}", "probe/{v}", "monitor/{v}",
    "agent/{v}", "fetcher/{v}", "spider/{v}",
]


def random_user_agent() -> str:
    """Generate a highly varied synthetic User-Agent string."""
    style = random.randint(0, 2)
    ver = f"{random.randint(1, 130)}.{random.randint(0, 9)}"
    if style == 0:
        engine = random.choice(_UA_ENGINES).format(v=ver)
        parts = [random.choice(_UA_PRODUCTS), random.choice(_UA_OS)]
        if engine:
            parts.append(engine)
        return " ".join(parts)
    elif style == 1:
        tool = random.choice(_UA_TOOLS).format(v=ver)
        vendor = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(4, 10)))
        return f"{vendor}/{tool}"
    else:
        # Fully random identifier — extreme cardinality
        name = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", k=random.randint(8, 32)))
        return name


_PATH_NOUNS = [
    "user", "order", "product", "session", "token", "invoice", "report",
    "event", "item", "record", "job", "task", "file", "blob", "asset",
    "message", "notification", "subscription", "payment", "account",
]
_PATH_VERBS = [
    "get", "list", "search", "create", "update", "delete", "export",
    "import", "process", "sync", "validate", "archive", "restore",
]
_PATH_PREFIXES = ["/api/v1", "/api/v2", "/api/v3", "/internal", "/admin", "/public", ""]


def random_path() -> str:
    """Generate a random URL path — produces unbounded cardinality."""
    style = random.randint(0, 3)
    if style == 0:
        # /api/v2/orders/<uuid>
        noun = random.choice(_PATH_NOUNS) + "s"
        uid = "%08x-%04x-%04x-%04x-%012x" % (
            random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFF),
            random.randint(0, 0xFFFF), random.randint(0, 0xFFFF),
            random.randint(0, 0xFFFFFFFFFFFF),
        )
        return f"{random.choice(_PATH_PREFIXES)}/{noun}/{uid}"
    elif style == 1:
        # /api/v1/users/12345/orders?page=3&limit=25
        noun1 = random.choice(_PATH_NOUNS) + "s"
        noun2 = random.choice(_PATH_NOUNS) + "s"
        resource_id = random.randint(1, 10_000_000)
        page = random.randint(1, 500)
        limit = random.choice([10, 20, 25, 50, 100])
        return f"{random.choice(_PATH_PREFIXES)}/{noun1}/{resource_id}/{noun2}?page={page}&limit={limit}"
    elif style == 2:
        # /admin/verb/noun  (random depth)
        depth = random.randint(1, 4)
        segments = [random.choice(_PATH_NOUNS + _PATH_VERBS) for _ in range(depth)]
        return "/" + "/".join(segments)
    else:
        # Totally random slug — maximum cardinality
        slug = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(6, 24)))
        return f"/{slug}"


def build_request_pool() -> list[RequestSpec]:
    """Build a weighted list of request specs that mimic real-world + attack traffic."""
    pool: list[RequestSpec] = []

    # ── Normal traffic (high weight) ─────────────────────────────────────────
    for path in NORMAL_PATHS:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": random.choice(BROWSER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=20,
        ))

    # ── Recon / scanning traffic (medium weight) ────────────────────────────
    for path in RECON_PATHS:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": random.choice(SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=5,
        ))

    # ── Missing resources / broken links (real 404s from Envoy) ──────────────
    for path in NOT_FOUND_PATHS:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": random.choice(BROWSER_AGENTS + SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=6,
        ))

    # ── Synthetic 5xx direct responses from Envoy ───────────────────────────
    for path in SERVER_ERROR_PATHS:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": random.choice(BROWSER_AGENTS + SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=4,
        ))

    # ── Real upstream failures and route timeouts ───────────────────────────
    for path in UPSTREAM_PROBLEM_PATHS:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": random.choice(BROWSER_AGENTS + SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=3,
        ))

    # ── Scanner agents on normal paths (low weight) ──────────────────────────
    for _ in range(8):
        pool.append(RequestSpec(
            method="GET",
            path=random.choice(NORMAL_PATHS),
            headers={"User-Agent": random.choice(SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=3,
        ))

    # ── Mutating methods on normal paths ────────────────────────────────────
    for _ in range(6):
        pool.append(RequestSpec(
            method=random.choice(EXTRA_METHODS),
            path=random.choice(NORMAL_PATHS),
            headers={"User-Agent": random.choice(BROWSER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS),
                     "Content-Type": "application/json"},
            body='{"key": "value"}',
            weight=4,
        ))

    # ── SQL-injection-like path attempts ───────────────────────────────────
    sqli_paths = [
        "/api/users?id=1' OR '1'='1",
        "/search?q=<script>alert(1)</script>",
        "/login?user=admin'--",
        "/api/data?sort=name;DROP TABLE users--",
    ]
    for path in sqli_paths:
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": "sqlmap/1.7 (https://sqlmap.org)",
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=2,
        ))

    # ── High-cardinality traffic (random UAs + random paths) ─────────────────
    # These entries regenerate their UA and path on *every* call to send_one()
    # because send_one() copies the RequestSpec; the pool entries below act as
    # sentinels — the path/UA are overwritten at dispatch time via the sentinel
    # marker CARDINALITY_SENTINEL on the weight field.
    #
    # Random user-agent only (fixed known path) — stresses UA cardinality
    for path in random.choices(NORMAL_PATHS + RECON_PATHS, k=15):
        pool.append(RequestSpec(
            method="GET",
            path=path,
            headers={"User-Agent": "__random_ua__",
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=-1,  # sentinel: UA re-rolled per request
        ))

    # Random path only (known UA category) — stresses path cardinality
    for _ in range(15):
        pool.append(RequestSpec(
            method=random.choice(["GET", "GET", "GET", "POST"]),
            path="__random_path__",
            headers={"User-Agent": random.choice(BROWSER_AGENTS + SCANNER_AGENTS),
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=-2,  # sentinel: path re-rolled per request
        ))

    # Both random — maximum cardinality
    for _ in range(10):
        pool.append(RequestSpec(
            method="GET",
            path="__random_path__",
            headers={"User-Agent": "__random_ua__",
                     "X-Forwarded-For": random.choice(SIMULATED_IPS)},
            weight=-3,  # sentinel: both re-rolled per request
        ))

    return pool


def weighted_choice(pool: list[RequestSpec]) -> RequestSpec:
    # Sentinel entries (weight < 0) are sampled with a fixed low probability
    # regardless of their weight value — use abs value clamped to 2.
    weights = [w if (w := r.weight) > 0 else 2 for r in pool]
    return random.choices(pool, weights=weights, k=1)[0]


def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=0)  # don't retry — we want to see errors
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# One session per worker thread (sessions are not concurrency-safe)
_thread_local = threading.local()


def _get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        _thread_local.session = make_session()
    return _thread_local.session


def send_one(pool: list[RequestSpec]) -> None:
    """Pick a random spec, copy its headers, and fire the request."""
    spec = weighted_choice(pool)
    # Copy headers so we don't mutate the shared pool entry
    headers = dict(spec.headers)
    headers["X-Forwarded-For"] = random.choice(SIMULATED_IPS)

    # Resolve cardinality sentinels
    path = random_path() if spec.path == "__random_path__" else spec.path
    if headers.get("User-Agent") == "__random_ua__":
        headers["User-Agent"] = random_user_agent()

    req = RequestSpec(
        method=spec.method,
        path=path,
        headers=headers,
        body=spec.body,
        weight=spec.weight,
    )
    send(_get_session(), req)


def send(session: requests.Session, spec: RequestSpec) -> None:
    url = f"{TARGET_URL}{spec.path}"
    try:
        resp = session.request(
            method=spec.method,
            url=url,
            headers=spec.headers,
            data=spec.body,
            timeout=5,
            allow_redirects=False,
        )
        log.info("%s %s → %s", spec.method, spec.path, resp.status_code)
    except requests.exceptions.ConnectionError:
        log.warning("Connection refused — Envoy not ready yet, retrying …")
        time.sleep(2)
    except requests.exceptions.Timeout:
        log.warning("Timeout on %s %s", spec.method, spec.path)
    except requests.exceptions.RequestException as exc:
        log.error("Request error: %s", exc)


def wait_for_envoy(session: requests.Session, max_wait: int = 120) -> None:
    """Block until Envoy responds or max_wait seconds elapsed."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        try:
            session.get(f"{TARGET_URL}/", timeout=3)
            log.info("Envoy is ready — starting load generation")
            return
        except requests.exceptions.RequestException:
            log.info("Waiting for Envoy at %s …", TARGET_URL)
            time.sleep(3)
    log.error("Envoy did not become ready within %ds — continuing anyway", max_wait)


def main() -> None:
    log.info("Target: %s  |  Rate: %.1f req/s  |  Workers: %d", TARGET_URL, RPS, WORKERS)
    init_session = make_session()
    wait_for_envoy(init_session)

    pool = build_request_pool()
    log.info("Request pool built with %d unique specs", len(pool))

    interval = 1.0 / RPS
    dispatched = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        while True:
            t0 = time.monotonic()
            executor.submit(send_one, pool)
            dispatched += 1
            if dispatched % 500 == 0:
                log.info("Dispatched %d requests so far", dispatched)
            elapsed = time.monotonic() - t0
            remaining = interval - elapsed
            if remaining > 0:
                time.sleep(remaining)


if __name__ == "__main__":
    main()
