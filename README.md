<p align="center">
  <img src="logo.png" width="120" height="120" alt="Server Hub logo">
</p>

<h1 align="center">Server Hub</h1>

<p align="center">
  A self-hosted dashboard for your applications and services — one page, no build step, zero third-party dependencies.
  <br>
  <a href="#features">Features</a> · <a href="#quick-start">Quick Start</a> · <a href="#configuration">Configuration</a> · <a href="#api">API</a> · <a href="#testing">Testing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.8-5E6AD2" alt="Python >=3.8">
  <img src="https://img.shields.io/badge/dependencies-0-22C55E" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/tests-181%20client%20%2B%2043%20server-22C55E" alt="Tests: 224 passing">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
</p>

---

Server Hub turns a list of links into a searchable, auto-categorized homepage served by a single-file Python server (stdlib only). It runs anywhere Python 3 is available — a small VPS, an LXC container, or Docker — with a minimal memory footprint.

There is no frontend build step and no npm/node toolchain: the whole dashboard is a static `index.html` that talks to one small HTTP server.

## Features

- **Adaptive layout** — Two-column dashboard on desktop (content left, sidebar right); service cards and category groups resize to content so the page stays compact.
- **Auto-categorization** — Services are grouped into 23 categories by keyword rules. No API key, no external service.
- **Search** — Fullscreen search overlay with live service suggestions; pressing Enter runs a web search (Google, DuckDuckGo, Bing, SearXNG, or Startpage) in a new tab.
- **Bookmarks** — A dedicated sidebar section for frequently used links, with optional per-link dot colors. Server-persisted.
- **Wallpapers** — Choose no background, a bundled gradient, or a custom image URL. The dashboard samples the image's brightness and adjusts glass/text contrast for readability. Wallpaper changes are smooth and viewport-locked, so adding services or navigating never re-zooms it.
- **Beszel integration** — Optional multi-server CPU / memory / disk monitoring by proxying a [Beszel](https://github.com/henrygd/beszel) hub. Falls back to single-host stats when unconfigured.
- **Status pings** — Best-effort health checks per service (up / down / checking), disableable per link.
- **System stats** — CPU / memory / disk usage bars from the host.
- **Links** — Add, edit, and delete links from the dashboard or settings. Stored server-side in `services.json`, shared across devices.
- **Personalization** — Page title, subtitle, greeting name, accent color, default domain, per-feature toggles. Persisted in `localStorage`.
- **Backup & restore** — Export settings, links, and bookmarks to a JSON file; import to restore.
- **Authentication** — Single-user login with an `HttpOnly` session cookie and per-IP brute-force lockout.

## Quick Start

### Docker (recommended)

Use the prebuilt image and CasaOS-ready compose file from the **[server-hub-docker](https://github.com/eco-null/server-hub-docker)** repository:

```bash
git clone https://github.com/eco-null/server-hub-docker.git
cd server-hub-docker

# 1. Set a strong password in docker-compose.yml (HUB_PASSWORD)
# 2. Start it
docker compose up -d
```

Open `http://<host>:8643` and sign in at `/login`. The container runs non-root, stores data on the host, and reports the host's CPU / memory / disk stats.

> **CasaOS:** Apps → Custom App → paste the compose file → set `HUB_USER` / `HUB_PASSWORD` → install. The image `ghcr.io/eco-null/server-hub:latest` is pulled automatically.

### Bare metal (Python 3)

```bash
git clone https://github.com/eco-null/server-hub.git
cd server-hub
HUB_PASSWORD=change-me python3 server.py
```

Open <http://localhost:8642> — sign in at `/login`, then use the dashboard.

## Configuration

Configuration is via environment variables. `HUB_PASSWORD` is required; the server refuses to start without it.

| Variable | Default | Description |
|---|---|---|
| `HUB_USER` | `admin` | Sign-in username. |
| `HUB_PASSWORD` | — (required) | Sign-in password. |
| `HUB_PORT` | `8642` | Listen port. |
| `HUB_HOST` | `0.0.0.0` | Bind address. |
| `BESZEL_URL` | *(empty)* | Beszel hub URL, e.g. `http://beszel:9520`. Empty disables multi-server stats. |
| `BESZEL_USER` | *(empty)* | Beszel account name used to fetch system stats. |
| `BESZEL_PASSWORD` | *(empty)* | Beszel account password. |
| `HUB_DISK_PATH` | `/` | Filesystem path read for the disk widget (Docker sets `/host` = host root). |

Generate a strong password with `openssl rand -base64 24`.

## Beszel Multi-Server Stats

Set `BESZEL_URL`, `BESZEL_USER`, and `BESZEL_PASSWORD` to monitor every server registered in your Beszel hub. Server Hub authenticates with Beszel's PocketBase API and renders per-system CPU / memory / disk bars, status, and uptime in the sidebar, refreshed every 15 seconds.

The Beszel account must be a member of the systems you want to see (add it in the Beszel UI, or enable `SHARE_ALL_SYSTEMS` on the hub). When Beszel is unconfigured or unreachable, the dashboard falls back to the single-host `/api/stats` widget.

## Multi-User Authentication (Supabase)

Server Hub supports two auth modes. The default single-user env auth remains
fully supported as a fallback; set `SUPABASE_URL` + `SUPABASE_ANON_KEY` to
enable **multi-user mode** with per-user data isolation (RLS).

| Variable | Default | Description |
|---|---|---|
| `SUPABASE_URL` | *(empty)* | e.g. `https://xxxx.supabase.co` — enables multi-user |
| `SUPABASE_ANON_KEY` | *(empty)* | Publishable anon key (not secret; RLS-scoped) |

### Schema setup (one-time)

Run `supabase-schema.sql` in the Supabase SQL Editor. It creates:

- `profiles` — `auth.users` 1:1, unique username
- `user_settings` — per-user `settings` + `layout` (JSONB) — dashboard personalization
- `user_services`, `user_bookmarks` — per-user services/bookmarks (was global `services.json`)
- `user_logs` — per-user **error/conflict logs** (`ERROR` / `WARN` / `CONFLICT` only)
- Row Level Security on every table (`auth.uid() = user_id`) — users can only see/edit their own rows
- `on_auth_user_created` trigger — auto-creates profile + settings row on signup

### Notes

- Data isolation is enforced by **PostgREST RLS**: the server proxies every data
  request with the user's own JWT (`Authorization: Bearer`), so a user can never
  read or mutate another user's rows (verified in tests).
- Passwords never touch Server Hub: Supabase Auth stores them (bcrypt).
- Built-in brute-force protection: Supabase rate-limits `/auth/v1/token`
  (1800 req/h/IP). A per-IP `LoginGuard` (5 attempts → 60 s lockout) adds a
  local first line of defense.
- CSRF: all mutating requests are same-origin checked (`Origin` /
  `Sec-Fetch-Site`); session cookie is `HttpOnly; SameSite=Lax` (+ `Secure`
  when behind HTTPS via `X-Forwarded-Proto`).
- Security headers are sent on every response: `nosniff`, `SAMEORIGIN`,
  `no-referrer`, and a `Content-Security-Policy`.
- Frontend errors are captured and written to the user's own `user_logs`
  (`/api/logs`), so per-user error history is separate by design.

## API

All endpoints return JSON and require an active session cookie, except `POST /login` and `POST /register`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Sign in; sets a 30-day `HttpOnly` session cookie. |
| `POST` | `/register` | Create account (multi-user mode). |
| `GET` | `/api/services` | List services (current user). |
| `POST` | `/api/services` | Create a service. |
| `PUT` | `/api/services/<id>` | Update a service. |
| `DELETE` | `/api/services/<id>` | Delete a service. |
| `GET` | `/api/bookmarks` | List bookmarks (current user). |
| `POST` | `/api/bookmarks` | Create a bookmark. |
| `PUT` | `/api/bookmarks/<id>` | Update a bookmark. |
| `DELETE` | `/api/bookmarks/<id>` | Delete a bookmark. |
| `GET` | `/api/settings` | Read user settings/layout (multi-user). |
| `PUT` | `/api/settings` | Save user settings/layout (multi-user). |
| `GET` | `/api/logs` | List current user's error/conflict logs. |
| `POST` | `/api/logs` | Log a frontend error for the current user. |
| `GET` | `/api/beszel` | Multi-server stats from Beszel (proxy). |
| `GET` | `/api/stats` | Single-host stats: `{ host, cpu, mem, disk }` (Linux `/proc`). |
| `GET` | `/api/me` | Current session user (email, username, user_id). |

Service object: `{ id, name, url, description, icon, ping, categoryOverride }`. Bookmark object: `{ id, name, url, icon, color }`. Request bodies are capped at 64 KB.

## Project Structure

| File | Purpose |
|---|---|
| `index.html` | Dashboard — layout, service grid, search, pings, clock, stats, bookmarks, wallpapers, CRUD, frontend error reporting. |
| `settings.html` | Settings page — theme, accent, wallpaper, features, link/bookmark editors, backup, Beszel status. |
| `login.html` | Login page. |
| `register.html` | Account creation page (multi-user mode). |
| `settings.js` | Shared settings layer (`localStorage` + server sync) and wallpaper application. |
| `categorize.js` | Category keyword rules and matcher. |
| `server.py` | Auth (Supabase + legacy), static serving, per-user services/bookmarks/settings/logs CRUD, stats, Beszel proxy. |
| `auth.py` | Supabase Auth + PostgREST client (stdlib only). |
| `supabase-schema.sql` | One-time multi-user schema (tables + RLS + trigger). |
| `test_server.py` | Server test suite (52 tests: legacy + security + Supabase mode). |
| `tests.html` | Browser test suite (181 assertions). |
| `SETUP-LXC.md` | Proxmox LXC deployment guide. |
| `SETUP.md` | Cloudflare Access guide for public domains. |

## Testing

```bash
# Server suite
python3 -m unittest test_server

# Browser suite — serve and open in a browser
python3 -m http.server 8000
# http://localhost:8000/tests.html
```

A green `ALL GREEN` summary means all assertions passed: 43 server tests and 181 client assertions.

## Deployment

- **Docker / CasaOS** — the official image and compose file live in [server-hub-docker](https://github.com/eco-null/server-hub-docker).
- **Proxmox LXC** — see [`SETUP-LXC.md`](SETUP-LXC.md) for a systemd-based deployment in ~5 minutes.
- **Cloudflare Access** — see [`SETUP.md`](SETUP.md) to put SSO in front of a public domain.

## Security

- Credentials are read from environment variables at startup; nothing is shipped in the repo.
- `HttpOnly` session cookies (30-day TTL), per-IP lockout after 5 failed attempts (60 s).
- Request body size limits (64 KB) on login and API routes.
- Only `/login` is public; all other routes return `401` until signed in.
- Beszel credentials are server-side environment variables only — never exposed to the browser.
- The Docker image runs as a non-root user and drops privileges before starting the server.

## Known Limitations

- Links and bookmarks are stored in `services.json` on the server; the server must be running to add, edit, or delete.
- Sessions are held in memory; restarting `server.py` signs everyone out.
- Single-host stats read `/proc` and are Linux-only (bars render as `—` elsewhere). Beszel multi-server stats have no such dependency.
- `file://` preview cannot persist settings (browsers block `localStorage` on opaque origins). Serve over HTTP.

## License

[MIT](LICENSE)
