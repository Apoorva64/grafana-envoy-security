/**
 * k6 load generator for the Envoy security dashboard.
 *
 * Generates realistic mixed traffic — normal requests, error-triggering paths,
 * 5xx responses, upstream failures, timeouts, suspicious user agents, and
 * different HTTP methods — so the security panels in Grafana have interesting
 * data to display right away.
 *
 * Environment variables:
 *   TARGET_URL            (default: http://envoy:10000)
 *   REQUESTS_PER_SECOND   (default: 500)
 *   VUS                   (default: 100)  pre-allocated virtual users
 */

import http from 'k6/http';
import { sleep } from 'k6';

// ── Configuration ─────────────────────────────────────────────────────────────
const TARGET_URL = (__ENV.TARGET_URL || 'http://envoy:10000').replace(/\/$/, '');
const RPS = parseInt(__ENV.REQUESTS_PER_SECOND || '500');
const VUS = parseInt(__ENV.VUS || '100');

export const options = {
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: RPS,
      timeUnit: '1s',
      duration: '999999h', // run indefinitely
      preAllocatedVUs: VUS,
      maxVUs: VUS * 3,
    },
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/** Weighted random selection from an array of [value, weight] pairs. */
function weightedChoice(items) {
  let total = 0;
  for (let i = 0; i < items.length; i++) total += items[i][1];
  let r = Math.random() * total;
  for (const [item, weight] of items) {
    r -= weight;
    if (r <= 0) return item;
  }
  return items[items.length - 1][0];
}

// ── Traffic profiles ──────────────────────────────────────────────────────────

const NORMAL_PATHS = [
  '/', '/health', '/api/v1/users', '/api/v1/products', '/api/v1/orders',
  '/about', '/contact', '/login', '/dashboard', '/static/app.js',
];

const RECON_PATHS = [
  '/.env', '/.git/config', '/wp-admin/', '/wp-login.php',
  '/admin', '/admin/login', '/phpmyadmin/', '/.htaccess',
  '/etc/passwd', '/api/v1/../../etc/passwd',
  '/actuator/env', '/actuator/health',
  '/.well-known/security.txt', '/robots.txt',
  '/server-status', '/.DS_Store',
  '/config.json', '/credentials.json',
  '/api/swagger.json', '/openapi.json',
];

const NOT_FOUND_PATHS = [
  '/missing', '/missing/favicon.ico', '/missing/app.bundle.js',
  '/not-found', '/not-found/profile',
  '/old-api/v1/users', '/old-api/v2/orders',
  '/deleted/page.html', '/deleted/assets/logo.png',
];

const SERVER_ERROR_PATHS = [
  '/server-error', '/server-error/api/v1/users', '/server-error/api/v1/orders',
  '/bad-gateway', '/bad-gateway/api/v1/products',
  '/unavailable', '/unavailable/search',
  '/gateway-timeout', '/gateway-timeout/report',
];

const UPSTREAM_PROBLEM_PATHS = [
  '/slow', '/slow/api/v1/report', '/slow/export.csv', '/slow/dashboard',
  '/upstream-unavailable', '/upstream-unavailable/api/v1/users', '/upstream-unavailable/health',
];

const SCANNER_AGENTS = [
  'sqlmap/1.7 (https://sqlmap.org)',
  'Nikto/2.1.6',
  'masscan/1.3',
  'Mozilla/5.0 (compatible; DirBuster-1.0)',
  'WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)',
  'Python/3.x httpx/0.24',
  'Go-http-client/1.1',
  'Nuclei - Open-source vulnerability scanner',
  'ffuf/2.1.0',
  'ZGrab/0.x',
  'curl/8.2.1',
  'Hydra',
  'wfuzz/3.1.0',
];

const BROWSER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
];

// Simulated client IPs (via X-Forwarded-For) with geographic weights.
// IPs are real routable addresses; weights reflect relative web-traffic volume
// per region so the GeoIP heatmap in Grafana looks plausible.
const SIMULATED_IPS_WEIGHTED = [
  // ── North America ──────────────────────────────────────────────────────────
  ['8.8.8.8',          20],  // Google DNS, Mountain View CA
  ['8.8.4.4',          15],  // Google DNS (secondary)
  ['4.2.2.1',          12],  // Level3, US
  ['4.2.2.2',          12],
  ['23.185.0.1',       10],  // Fastly CDN edge
  ['104.16.0.1',       10],  // Cloudflare, US
  ['198.41.0.4',        8],  // Verisign, US
  ['199.7.91.13',       8],  // ICANN
  ['64.233.160.0',     10],  // Google, US
  ['45.33.32.156',      6],  // Linode (attacker VPS, US)
  ['99.79.49.1',        5],  // AWS Canada East
  ['206.167.0.1',       4],  // Shaw, Calgary
  ['187.174.0.1',       4],  // Telmex, Mexico City
  ['189.196.0.1',       3],  // Axtel, Mexico
  // ── Europe ────────────────────────────────────────────────────────────────
  ['217.0.0.1',        12],  // Deutsche Telekom
  ['80.237.0.1',        8],  // Vodafone DE
  ['85.214.0.1',        6],  // Strato AG, Berlin (VPS)
  ['46.4.0.1',          8],  // Hetzner, Nuremberg
  ['144.76.0.1',        6],  // Hetzner
  ['90.0.0.1',          8],  // Orange France
  ['212.27.0.1',        6],  // Proxad/Free SAS
  ['51.77.0.1',         5],  // OVH, Gravelines
  ['81.2.69.0',         8],  // BT UK
  ['195.238.0.1',       6],  // Virgin Media
  ['51.148.0.1',        5],  // Microsoft Azure UK South
  ['80.101.0.1',        7],  // KPN Netherlands
  ['185.220.101.1',     5],  // Tor exit node range
  ['194.165.0.1',       4],  // Leaseweb, Amsterdam
  ['91.108.4.1',        8],  // Telegram (bot traffic)
  ['5.188.0.1',         6],  // Yandex Cloud
  ['176.74.0.1',        5],  // Petersburg Internet Network
  ['185.234.218.1',     4],  // Serverius (scanner-heavy range)
  ['31.0.0.1',          4],  // Polkomtel
  ['195.67.0.1',        3],  // Tele2 Sweden
  ['80.58.0.1',         5],  // Telefonica España
  ['195.55.0.1',        3],  // Vodafone ES
  ['62.101.0.1',        4],  // Telecom Italia
  ['46.162.0.1',        4],  // Kyivstar
  ['91.206.0.1',        3],  // DataHata, Kyiv
  // ── Asia-Pacific ──────────────────────────────────────────────────────────
  ['1.180.0.1',        16],  // China Telecom
  ['58.14.0.1',        14],  // China Unicom
  ['120.192.0.1',      10],  // China Mobile
  ['61.135.169.121',    8],  // Baidu crawler
  ['202.96.0.1',        6],  // China Telecom
  ['14.215.0.1',        6],  // Tencent
  ['1.6.0.1',          12],  // BSNL India
  ['117.195.0.1',       8],  // Airtel India
  ['59.144.0.1',        6],  // VSNL (Tata)
  ['103.21.0.1',        5],  // Cloudflare India PoP
  ['203.104.0.1',       8],  // NTT Communications
  ['126.0.0.1',         7],  // SoftBank BB
  ['220.110.0.1',       5],  // KDDI
  ['1.246.0.1',         7],  // SK Telecom
  ['175.213.0.1',       5],  // LG Uplus
  ['1.128.0.1',         7],  // Telstra
  ['121.200.0.1',       4],  // Optus
  ['203.0.0.1',         3],  // AAPT, Australia
  ['175.41.128.1',      6],  // AWS APac
  ['202.166.0.1',       4],  // Singtel
  ['114.122.0.1',       5],  // Telkomsel
  ['36.69.0.1',         4],  // Telkom Indonesia
  ['14.161.0.1',        4],  // VNPT Vietnam
  ['203.80.0.1',        4],  // HKT
  ['168.95.0.1',        4],  // Chunghwa Telecom
  ['114.42.0.1',        3],  // PTCL Pakistan
  ['103.152.0.1',       2],  // Grameenphone Bangladesh
  // ── Middle East ───────────────────────────────────────────────────────────
  ['78.162.0.1',        5],  // Turk Telekom
  ['37.0.0.1',          4],  // STC Saudi Arabia
  ['212.14.0.1',        3],  // Mobily
  ['185.93.0.1',        3],  // du Telecom UAE
  ['82.80.0.1',         3],  // Partner Communications Israel
  ['94.74.0.1',         3],  // Shatel, Tehran
  // ── Africa ────────────────────────────────────────────────────────────────
  ['197.210.0.1',       5],  // MTN Nigeria
  ['41.206.0.1',        3],  // Spectranet Nigeria
  ['196.25.0.1',        4],  // Telkom SA
  ['105.0.0.1',         3],  // Vodacom SA
  ['197.32.0.1',        3],  // TE Data Egypt
  ['196.200.0.1',       2],  // Safaricom Kenya
  ['196.188.0.1',       2],  // Ethio Telecom
  // ── Latin America ─────────────────────────────────────────────────────────
  ['189.1.0.1',         9],  // Claro Brasil
  ['177.0.0.1',         8],  // NET/Claro
  ['200.152.0.1',       6],  // GVT / Vivo
  ['179.108.0.1',       5],  // Oi Telecom
  ['190.0.0.1',         5],  // Telecom Argentina
  ['200.49.0.1',        3],  // Fibertel
  ['190.242.0.1',       3],  // ETB Colombia
  ['181.65.0.1',        2],  // Claro Colombia
  ['200.75.0.1',        3],  // Entel Chile
  // ── Known attack / scan infrastructure ────────────────────────────────────
  ['198.20.69.74',      4],  // Shodan
  ['198.20.70.114',     4],  // Shodan
  ['198.20.99.130',     4],  // Shodan
  ['162.142.125.1',     3],  // Censys
  ['167.94.138.1',      3],  // Censys
  ['193.32.162.1',      3],  // Selectel, Russia (bulletproof)
  ['185.220.100.1',     3],  // Tor exit, Netherlands
  ['89.234.157.254',    2],  // Tor / FDN, France
];

const EXTRA_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

const SQLI_PATHS = [
  "/api/users?id=1' OR '1'='1",
  '/search?q=<script>alert(1)</script>',
  "/login?user=admin'--",
  '/api/data?sort=name;DROP TABLE users--',
];

// ── Cardinality helpers ───────────────────────────────────────────────────────

const _UA_PRODUCTS = [
  'Mozilla/5.0', 'curl', 'python-requests', 'axios', 'okhttp', 'Go-http-client',
  'Java/HttpClient', 'Dalvik', 'libwww-perl', 'wget', 'HTTPie', 'Scrapy',
];
const _UA_OS = [
  '(Windows NT 10.0; Win64; x64)', '(Macintosh; Intel Mac OS X 14_6)',
  '(X11; Linux x86_64)', '(Android 14; Pixel 8)', '(iPhone; CPU iPhone OS 17_5)',
  '(compatible; Bot/1.0)', '(Linux; arm64)', '(FreeBSD; amd64)',
];
const _UA_ENGINES = [
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36',
  'Gecko/20100101 Firefox/{v}',
  'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} Safari/605.1.15',
  'rv:{v}',
  '',
];
const _UA_TOOLS = [
  'scanner/{v}', 'bot/{v}', 'crawler/{v}', 'probe/{v}', 'monitor/{v}',
  'agent/{v}', 'fetcher/{v}', 'spider/{v}',
];

function randomUserAgent() {
  const style = Math.floor(Math.random() * 3);
  const ver = `${Math.floor(Math.random() * 130) + 1}.${Math.floor(Math.random() * 10)}`;
  if (style === 0) {
    const engine = randomChoice(_UA_ENGINES).replace('{v}', ver);
    const parts = [randomChoice(_UA_PRODUCTS), randomChoice(_UA_OS)];
    if (engine) parts.push(engine);
    return parts.join(' ');
  } else if (style === 1) {
    const tool = randomChoice(_UA_TOOLS).replace('{v}', ver);
    const len = Math.floor(Math.random() * 6) + 4;
    const vendor = Array.from({ length: len }, () =>
      'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]
    ).join('');
    return `${vendor}/${tool}`;
  } else {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const len = Math.floor(Math.random() * 24) + 8;
    return Array.from({ length: len }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join('');
  }
}

const _PATH_NOUNS = [
  'user', 'order', 'product', 'session', 'token', 'invoice', 'report',
  'event', 'item', 'record', 'job', 'task', 'file', 'blob', 'asset',
  'message', 'notification', 'subscription', 'payment', 'account',
];
const _PATH_VERBS = [
  'get', 'list', 'search', 'create', 'update', 'delete', 'export',
  'import', 'process', 'sync', 'validate', 'archive', 'restore',
];
const _PATH_PREFIXES = ['/api/v1', '/api/v2', '/api/v3', '/internal', '/admin', '/public', ''];

function randomPath() {
  const style = Math.floor(Math.random() * 4);
  const noun = () => randomChoice(_PATH_NOUNS) + 's';
  if (style === 0) {
    const uid = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.replace(/x/g, () =>
      Math.floor(Math.random() * 16).toString(16)
    );
    return `${randomChoice(_PATH_PREFIXES)}/${noun()}/${uid}`;
  } else if (style === 1) {
    const id = Math.floor(Math.random() * 10_000_000) + 1;
    const page = Math.floor(Math.random() * 500) + 1;
    const limit = randomChoice([10, 20, 25, 50, 100]);
    return `${randomChoice(_PATH_PREFIXES)}/${noun()}/${id}/${noun()}?page=${page}&limit=${limit}`;
  } else if (style === 2) {
    const depth = Math.floor(Math.random() * 4) + 1;
    const segs = Array.from({ length: depth }, () =>
      randomChoice([..._PATH_NOUNS, ..._PATH_VERBS])
    );
    return '/' + segs.join('/');
  } else {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-';
    const len = Math.floor(Math.random() * 18) + 6;
    return '/' + Array.from({ length: len }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join('');
  }
}

// ── Request pool ──────────────────────────────────────────────────────────────
// Each entry: [method, path, headers, body, weight]
// weight < 0  →  cardinality sentinel; sampled with weight=2 and resolved at
//                dispatch time (path / UA regenerated per request).

const REQUEST_POOL = [];

// Normal browser traffic (high weight)
for (const path of NORMAL_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': randomChoice(BROWSER_AGENTS) }, null, 20]);
}

// Recon / scanning traffic (medium weight)
for (const path of RECON_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': randomChoice(SCANNER_AGENTS) }, null, 5]);
}

// Missing resources — real 404s from Envoy
for (const path of NOT_FOUND_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': randomChoice([...BROWSER_AGENTS, ...SCANNER_AGENTS]) }, null, 6]);
}

// Synthetic 5xx direct responses from Envoy
for (const path of SERVER_ERROR_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': randomChoice([...BROWSER_AGENTS, ...SCANNER_AGENTS]) }, null, 4]);
}

// Real upstream failures and route timeouts
for (const path of UPSTREAM_PROBLEM_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': randomChoice([...BROWSER_AGENTS, ...SCANNER_AGENTS]) }, null, 3]);
}

// Scanner agents on normal paths
for (let i = 0; i < 8; i++) {
  REQUEST_POOL.push(['GET', randomChoice(NORMAL_PATHS), { 'User-Agent': randomChoice(SCANNER_AGENTS) }, null, 3]);
}

// Mutating HTTP methods on normal paths
for (let i = 0; i < 6; i++) {
  REQUEST_POOL.push([
    randomChoice(EXTRA_METHODS),
    randomChoice(NORMAL_PATHS),
    { 'User-Agent': randomChoice(BROWSER_AGENTS), 'Content-Type': 'application/json' },
    '{"key": "value"}',
    4,
  ]);
}

// SQL-injection-like path attempts
for (const path of SQLI_PATHS) {
  REQUEST_POOL.push(['GET', path, { 'User-Agent': 'sqlmap/1.7 (https://sqlmap.org)' }, null, 2]);
}

// Cardinality sentinels — random UA (weight sentinel -1)
for (let i = 0; i < 15; i++) {
  REQUEST_POOL.push([
    'GET',
    randomChoice([...NORMAL_PATHS, ...RECON_PATHS]),
    { 'User-Agent': '__random_ua__' },
    null,
    -1,
  ]);
}

// Cardinality sentinels — random path (weight sentinel -2)
for (let i = 0; i < 15; i++) {
  REQUEST_POOL.push([
    randomChoice(['GET', 'GET', 'GET', 'POST']),
    '__random_path__',
    { 'User-Agent': randomChoice([...BROWSER_AGENTS, ...SCANNER_AGENTS]) },
    null,
    -2,
  ]);
}

// Cardinality sentinels — both random (weight sentinel -3)
for (let i = 0; i < 10; i++) {
  REQUEST_POOL.push(['GET', '__random_path__', { 'User-Agent': '__random_ua__' }, null, -3]);
}

function pickFromPool() {
  const weights = REQUEST_POOL.map(([, , , , w]) => (w < 0 ? 2 : w));
  const total = weights.reduce((a, b) => a + b, 0);
  let r = Math.random() * total;
  for (let i = 0; i < REQUEST_POOL.length; i++) {
    r -= weights[i];
    if (r <= 0) return REQUEST_POOL[i];
  }
  return REQUEST_POOL[REQUEST_POOL.length - 1];
}

// ── Envoy readiness check (runs once before VUs start) ────────────────────────
export function setup() {
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt++) {
    const res = http.get(`${TARGET_URL}/`, { timeout: '3s', redirects: 0 });
    if (res.status > 0) {
      console.log(`Envoy is ready — starting load generation (status ${res.status})`);
      ready = true;
      break;
    }
    console.log(`Waiting for Envoy at ${TARGET_URL} … (attempt ${attempt + 1})`);
    sleep(3);
  }
  if (!ready) {
    console.warn(`Envoy did not become ready within 120s — proceeding anyway`);
  }
}

// ── Default VU function ───────────────────────────────────────────────────────
export default function () {
  const [method, rawPath, rawHeaders, body] = pickFromPool();

  // Resolve cardinality sentinels
  const path = rawPath === '__random_path__' ? randomPath() : rawPath;
  const headers = Object.assign({}, rawHeaders, {
    'X-Forwarded-For': weightedChoice(SIMULATED_IPS_WEIGHTED),
  });
  if (headers['User-Agent'] === '__random_ua__') {
    headers['User-Agent'] = randomUserAgent();
  }

  const params = { headers, redirects: 0, timeout: '5s' };
  http.request(method, `${TARGET_URL}${path}`, body || null, params);
}
