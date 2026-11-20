# Honeypot 2.O — by Virk7

A drop-in gateway you place in front of a network or website. Traffic from
your organization's own network passes straight through to the real
site. Everyone else is silently redirected into an instrumented honeypot
that logs what they do, guesses what they're after, and tries to get their
geolocation via the browser — all viewable in a local admin dashboard.

## How it works

```
                  ┌───────────────────────┐
  All traffic ──▶ │   Honeypot 2.O        │
                  │   gateway (:8080)     │
                  └──────────┬────────────┘
                             │
             ┌───────────────┴───────────────┐
             │ is source IP in orgNetworks?   │
             └───────────────┬───────────────┘
                 yes ◀────────┴────────▶ no
                  │                        │
                  ▼                        ▼
        reverse-proxy to           serve decoy site,
        your real site             log every request,
        (realSiteTarget)           classify intent,
                                    ask browser for
                                    geolocation,
                                    fingerprint device
                                            │
                                            ▼
                                   SQLite database
                                            │
                                            ▼
                              Admin dashboard (:8081)
```

- **Org detection**: source IP checked against CIDR ranges in
  `orgNetworks` (plus an optional exact-IP `orgAllowList` for remote staff).
- **Honeypot capture**: every request from non-org traffic is logged —
  method, path, query, headers, POST bodies (including any credentials
  typed into the decoy login form), user agent, and a session cookie that
  ties repeat visits together.
- **Aim classification**: a small rule set labels each request
  (credential harvesting, admin-panel probing, SQL injection attempt,
  path traversal, scanner/bot, etc.) so you can see the likely goal at a
  glance.
- **Geolocation**: the decoy page's JS calls the browser's
  `navigator.geolocation` API, which prompts the visitor for permission.
  If granted, precise coordinates are recorded. IP-based (offline
  MaxMind-lite) geolocation is always recorded as a fallback/cross-check.
- **Admin dashboard**: login-protected (proper session cookie, with a
  working Logout), shows aggregate stats, a sortable session list, a full
  per-session timeline with credentials, geolocation and classified
  intent, and a "Reset all data" button to wipe the database when you
  want a clean slate (e.g. before/after a demo).

## Requirements

- Node.js 18+
- A Linux (or macOS/WSL) terminal
- Build tools for the native SQLite module (`better-sqlite3`): on Debian/
  Ubuntu, `sudo apt install build-essential python3` if `npm install` fails
  to compile it.

## Install

```bash
cd honeypot2.0
npm install
```

## Configure

You don't need a separate setup step — just run `honeypot2 start` (see below). If no `config.json` exists yet, it will ask you the setup questions right then and create one before launching.

If you'd rather set it up without starting the server yet:

```bash
node bin/honeypot2.js init
```

Or configure manually:

```bash
cp config.example.json config.json
# edit config.json: realSiteTarget, orgNetworks, adminUser/adminPassword, ports
```

Key fields in `config.json`:

| Field | Purpose |
|---|---|
| `realSiteTarget` | Where org traffic is proxied to (your actual site) |
| `orgNetworks` | CIDR ranges treated as trusted org traffic |
| `orgAllowList` | Individual IPs always treated as org traffic |
| `trustProxyHeaders` | Only set `true` if you control the upstream LB/CDN — otherwise `X-Forwarded-For` can be spoofed to fake org traffic |
| `gatewayPort` / `adminPort` | Ports for the public gateway and the private admin dashboard |
| `adminUser` / `adminPassword` | Basic-auth credentials for the dashboard — change these before deploying |
| `dbPath` | SQLite file location |

## Run

```bash
npm install -g .        # optional: makes `honeypot2` available globally
honeypot2 start
# or, without global install:
node bin/honeypot2.js start --config ./config.json
```

- Public gateway: `http://<host>:8080`
- Admin dashboard: `http://<host>:8081` (basic auth)

Put the gateway wherever traffic first arrives (e.g. as the target behind
your load balancer/reverse proxy, or directly on the edge) so all inbound
requests hit it first.

## Data storage

Everything is stored locally in a single SQLite file (`dbPath`, default
`./data/honeypot.db`) — no data leaves the machine. Tables: `sessions`,
`requests`, `credential_attempts`. Back it up or rotate it like any other
log file.

## Responsible use

Only deploy this on infrastructure you own or are explicitly authorized to
protect/test. Logging credentials typed by visitors, fingerprinting
devices, and requesting geolocation are deception techniques intended for
defensive monitoring of unauthorized access attempts against your own
systems — using them against traffic you don't have authorization to
monitor may violate wiretapping, computer-misuse, or privacy laws
depending on your jurisdiction. Tell your own employees/users this exists
if required by local law or company policy, and keep the admin dashboard
credentials and captured data (which may include real people's mistyped
credentials or location data) secured and access-limited.

## Project layout

```
honeypot2.0/
├── bin/honeypot2.js        CLI (init / start)
├── config.example.json     Template config
├── src/
│   ├── config.js           Config loader/validator
│   ├── ipMatch.js          CIDR / org-IP matching
│   ├── geoip.js            Offline IP geolocation
│   ├── classify.js         Attacker-intent heuristics
│   ├── db.js               SQLite schema + queries
│   ├── server.js           Gateway app (proxy + honeypot)
│   └── routes/admin.js     Admin dashboard app
├── views/                  EJS templates for the dashboard
├── public/
│   ├── honeypot/           Decoy site + geolocation/fingerprint JS
│   └── admin/              Dashboard stylesheet
└── data/                   SQLite DB lives here by default
```
