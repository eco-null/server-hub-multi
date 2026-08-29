<p align="center">
  <img src="logo.png" width="120" height="120" alt="Server Hub logo">
</p>

<h1 align="center">Server Hub</h1>

<p align="center">
  A focused, self-hosted dashboard for the applications and services you use every day.
  <br>
  <a href="#features">Features</a> · <a href="#quick-start">Quick Start</a> · <a href="#configuration">Configuration</a> · <a href="#api">API</a> · <a href="#testing">Testing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-5E6AD2" alt="Python 3.8 or newer">
  <img src="https://img.shields.io/badge/runtime-stdlib%20only-22C55E" alt="Python standard library only">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
</p>

---

Server Hub brings self-hosted applications, infrastructure tools, and frequently used links into one private homepage. It combines a lightweight Python backend with a static frontend: there is no frontend build pipeline and no package installation required for the server.

The project supports two deployment models:

- **Vercel + Supabase** for a serverless, multi-user deployment with per-user data isolation.
- **Standalone Python** for a simple single-user installation on a VPS, Proxmox LXC, or another Linux host.

## Features

- **Personal dashboard** — responsive service cards, category sections, bookmarks, clock, greeting, page title, and subtitle.
- **Search** — filter services instantly and optionally send a query to Google, DuckDuckGo, Bing, Startpage, or a configured SearXNG instance.
- **Automatic categorization** — services are categorized locally from their name, URL, and description, with manual overrides when needed.
- **Service management** — add, edit, delete, reorder, and configure health pings for links from the dashboard or Settings.
- **Bookmarks** — manage a compact set of frequently used links with optional colors and icons.
- **Themes and wallpapers** — light, dark, or automatic theme; built-in gradients; custom image URLs; and contrast adjustments for readability.
- **System monitoring** — local CPU, memory, and disk statistics, plus optional multi-server monitoring through [Beszel](https://github.com/henrygd/beszel).
- **Multi-user accounts** — Supabase Auth registration/login with user-specific settings, services, bookmarks, and logs protected by Postgres RLS.
- **Two-factor authentication** — optional TOTP protection using an authenticator app.
- **Backup and restore** — export and import settings, services, and bookmarks as JSON.
- **Security controls** — signed `HttpOnly` sessions, CSRF checks, rate limiting, request-size limits, security headers, and path-traversal protection.

## Quick Start

### Vercel + Supabase (multi-user)

1. Create a Supabase project.
2. Run [`supabase-schema.sql`](supabase-schema.sql) once in the Supabase SQL Editor.
3. Import this repository into Vercel.
4. Add the environment variables described in [Configuration](#configuration).
5. Deploy and open the resulting Vercel URL.

Vercel uses [`api/index.py`](api/index.py) as the Python Function entry point. It adapts the existing backend to Vercel’s WSGI runtime, while static assets are served through the same application.

> Keep `SUPABASE_SERVICE_ROLE_KEY` private. It is only used by the server for administrative signup and must never be exposed to browser code.

### Standalone Python (single-user)

```bash
git clone https://github.com/eco-null/server-hub-multi.git
cd server-hub-multi
HUB_PASSWORD=change-me python3 server.py
```

Open <http://localhost:8642> and sign in with the configured username and password. For a persistent Proxmox LXC deployment, see [`SETUP-LXC.md`](SETUP-LXC.md).

## Configuration

Configuration is provided through environment variables. With Supabase variables present, Server Hub runs in multi-user mode. Without them, it falls back to single-user authentication.

| Variable | Default | Description |
|---|---|---|
| `SUPABASE_URL` | *(empty)* | Supabase project URL; enables multi-user mode when paired with `SUPABASE_ANON_KEY`. |
| `SUPABASE_ANON_KEY` | *(empty)* | Supabase publishable/anon key used for Auth and RLS-scoped requests. |
| `SUPABASE_SERVICE_ROLE_KEY` | *(empty)* | Optional server-only key for administrative signup flows. Never expose it publicly. |
| `SUPABASE_SERVICE_KEY` | *(empty)* | Backward-compatible alias for the service-role key. |
| `HUB_USER` | `admin` | Username in standalone single-user mode. |
| `HUB_PASSWORD` | — | Required in standalone mode; use a strong password. |
| `SESSION_SECRET` | *(generated locally)* | Stable signing key for sessions. **Required on Vercel** so sessions survive across instances. |
| `HUB_HOST` | `0.0.0.0` | Bind address for standalone mode. |
| `HUB_PORT` | `8642` | Listen port for standalone mode. |
| `HUB_DISK_PATH` | `/` | Filesystem path used for the local disk widget. Set to `/host` when the container exposes the host root there. |
| `BESZEL_URL` | *(empty)* | Optional Beszel hub URL, for example `http://beszel:9520`. |
| `BESZEL_USER` | *(empty)* | Beszel account used by the server-side proxy. |
| `BESZEL_PASSWORD` | *(empty)* | Beszel account password. |

Generate secrets with:

```bash
openssl rand -base64 32
```

### Supabase setup

The schema creates the following tables and policies:

- `profiles` — user profile and unique username.
- `user_settings` — per-user dashboard settings and layout.
- `user_services` and `user_bookmarks` — per-user links and bookmarks.
- `user_logs` — per-user frontend error and conflict logs.
- Row Level Security policies that restrict every record to its owning `auth.uid()`.
- A signup trigger that creates the initial profile and settings row.

Passwords remain in Supabase Auth. Server Hub passes the signed-in user’s token through to the database API; it does not share data between users.

### Beszel monitoring

Set `BESZEL_URL`, `BESZEL_USER`, and `BESZEL_PASSWORD` to show CPU, memory, disk, status, and uptime for systems visible to that Beszel account. The dashboard refreshes this data periodically. If Beszel is unavailable or not configured, the local `/api/stats` widget remains available where the host exposes Linux `/proc` statistics.

## API

All API endpoints require an authenticated session unless noted otherwise. Mutating requests must be same-origin.

| Method | Path | Description |
|---|---|---|
| `POST` | `/login` | Sign in; supports username/email and the second TOTP step. |
| `POST` | `/register` | Create a Supabase account. |
| `GET` | `/logout` | End the current session. |
| `GET` | `/api/me` | Return the current user. |
| `GET/POST` | `/api/services` | List or create services. |
| `PUT/DELETE` | `/api/services/<id>` | Update or delete a service. |
| `GET/POST` | `/api/bookmarks` | List or create bookmarks. |
| `PUT/DELETE` | `/api/bookmarks/<id>` | Update or delete a bookmark. |
| `GET/PUT` | `/api/settings` | Read or save settings and layout. |
| `GET/POST` | `/api/logs` | Read or record frontend error/conflict logs. |
| `GET` | `/api/stats` | Return local host CPU, memory, and disk statistics. |
| `GET/POST` | `/api/beszel` | Read Beszel systems or test the configured connection. |
| `GET` | `/api/2fa/setup` | Create a pending TOTP setup payload. |
| `POST` | `/api/2fa/enable` | Enable TOTP after code verification. |
| `POST` | `/api/2fa/disable` | Disable TOTP after code verification. |

Service objects use `{ id, name, url, description, icon, ping, categoryOverride }`. Bookmark objects use `{ id, name, url, icon, color }`. JSON request bodies are limited to 64 KiB.

## Project Structure

| File | Purpose |
|---|---|
| `index.html` | Main dashboard, search, service/bookmark editors, pings, stats, and frontend error reporting. |
| `settings.html` | Theme, wallpaper, feature toggles, Beszel, 2FA, link management, and backup/restore. |
| `login.html` | Combined sign-in and account creation interface, including the TOTP step. |
| `register.html` | Compatibility entry point for the registration route. |
| `settings.js` | Shared settings persistence, local storage, server synchronization, and wallpaper handling. |
| `categorize.js` | Local category keyword rules and matcher. |
| `server.py` | Standalone HTTP server, authentication, API routes, persistence, statistics, and Beszel proxy. |
| `api/index.py` | Vercel WSGI bridge for the Python server. |
| `auth.py` | Dependency-free Supabase Auth and PostgREST client. |
| `supabase-schema.sql` | Supabase tables, RLS policies, triggers, and signup helper functions. |
| `services.json` | Standalone-mode service/bookmark storage; the checked-in file starts empty. |
| `test_server.py` | Python integration and security test suite. |
| `tests.html` | Browser-side test suite. |
| `SETUP-LXC.md` | Proxmox LXC and systemd deployment guide. |
| `SETUP.md` | Cloudflare Access and public-domain hardening guide. |

## Testing

Run the server suite with:

```bash
python3 -m unittest test_server
```

For the browser suite, serve the repository over HTTP and open `tests.html`:

```bash
python3 -m http.server 8000
```

Then visit <http://localhost:8000/tests.html>. Serving over HTTP is important because browsers may restrict `localStorage` on `file://` URLs.

## Deployment Notes

- **Vercel** — use the included [`vercel.json`](vercel.json), set `SESSION_SECRET`, and configure Supabase variables.
- **Proxmox LXC** — follow [`SETUP-LXC.md`](SETUP-LXC.md) for a systemd service and persistent `services.json`.
- **Cloudflare Access** — follow [`SETUP.md`](SETUP.md) when placing an additional edge authentication layer in front of a public deployment.

## Security

- Supabase mode isolates user data with Postgres RLS.
- Sessions use signed cookies with `HttpOnly`, `SameSite=Lax`, and `Secure` when HTTPS is detected.
- Passwords are handled by Supabase Auth in multi-user mode and are read from environment variables in standalone mode.
- Login and registration include per-IP rate limiting; API and login request bodies are capped at 64 KiB.
- Mutating requests enforce same-origin checks, and responses include `nosniff`, `SAMEORIGIN`, `no-referrer`, and CSP-related protections.
- Beszel credentials and TOTP secrets are kept server-side and are not returned to the browser.

## Known Limitations

- Standalone-mode sessions are held in memory; restarting `server.py` signs users out.
- Standalone-mode links and bookmarks are persisted in `services.json`; back up this file with the deployment.
- Local system statistics depend on Linux `/proc`; use Beszel for cross-host monitoring.
- The default frontend loads Tailwind, fonts, QRCode.js, and optional wallpaper assets from CDNs. A network-restricted deployment should vendor or replace these assets.

## License

[MIT](LICENSE)
