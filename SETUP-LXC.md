# Host on Proxmox LXC (no nginx, no cloudflared required)

Goal: a single Debian LXC container on your Proxmox node runs `server.py`
(no third-party packages) serving the static files behind a styled login page.
TLS/HTTPS can be added later from the Cloudflare Zero Trust panel via a
Cloudflare Tunnel — the container needs no nginx and no public port
configuration for that either.

```
┌────────────────────────────────┐
│  Proxmox host                  │
│  ┌──────────────────────────┐  │
│  │ LXC: server-hub          │  │
│  │  server.py  :8642        │  │
│  │  (Python 3 stdlib only)  │  │
│  └──────────────────────────┘  │
└────────────────────────────────┘
          │  HUB_HOST=0.0.0.0
          ▼
    Browser → /login → dashboard
```

Total cost: ~30 MB RAM, ~10 MB disk. ~5 minutes to set up.

---

## 1. Create the LXC container

In the Proxmox Web UI:

1. Top-right **Create CT**.
2. **General**
   - **Hostname:** `server-hub`
   - **Password / SSH key:** set root password + paste your public key for easy `ssh root@<container-ip>`.
3. **Template** — Download a Debian 12 template once if needed (`Storage → vmbr0 → Templates → Debian-12`), then select it.
4. **Disks** — 4 GB root disk is plenty.
5. **CPU** — 1 core.
6. **Memory** — 512 MB (swap 0). The container will idle at ~30 MB.
7. **Network**
   - DHCP is fine; or static `192.168.x.x/24`, gateway `192.168.x.1`.
   - **DNS:** inherit from host.
8. **Confirm → Create.**

Start it, then enter the console or `ssh` in.

---

## 2. Get the files in

`server.py` needs nothing installed — Python 3 is already on Debian 12 (`apt install -y python3` if your template lacks it). Create the folder and copy the 7 files (`index.html`, `categorize.js`, `settings.js`, `settings.html`, `tests.html`, `login.html`, `server.py`) to `/srv/server-hub/`. Pick **one** method:

**A. From your desktop via scp (easiest):**
```bash
# create the folder once on the container (it does not exist on a fresh install):
ssh root@<container-ip> "mkdir -p /srv/server-hub"

# from your workstation, in the project folder:
scp index.html categorize.js settings.js settings.html tests.html login.html server.py \
  root@<container-ip>:/srv/server-hub/
```

**B. Or clone from a private Git repo:**
```bash
apt install -y git
git clone https://github.com/you/server-hub.git /srv/server-hub
```

---

## 3. Run `server.py` as a systemd service

`/etc/systemd/system/server-hub.service`:

```ini
[Unit]
Description=Server Hub (static + login + stats)
After=network.target

[Service]
WorkingDirectory=/srv/server-hub
Environment=HUB_USER=admin
Environment=HUB_PASSWORD=CHANGE_ME_LONG_RANDOM
Environment=HUB_PORT=8642
Environment=HUB_HOST=0.0.0.0
ExecStart=/usr/bin/python3 /srv/server-hub/server.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

> `HUB_PASSWORD` is required — `server.py` refuses to start without it. Generate a long random one: `openssl rand -base64 24`.

**The unit above ships with the placeholder `CHANGE_ME_LONG_RANDOM` — replace it with your real password before the first start:**

```bash
# generate a password and paste it into the HUB_PASSWORD= line in the unit:
openssl rand -base64 24
nano /etc/systemd/system/server-hub.service

# restrict the unit file to root, then start:
chmod 600 /etc/systemd/system/server-hub.service
systemctl daemon-reload
systemctl enable --now server-hub
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8642/login   # → 200
```

That's it — the login page is served at `/login`, unauthenticated requests to `/` are redirected there, and `/api/stats` / `/api/services` / `/api/me` return `401` until you sign in. Auth is enforced by `server.py` itself, so there is no nginx config and no edge-side policy to write.

### Services data

Added links are stored in `services.json` in the same directory as `server.py` (`/srv/server-hub/services.json`). It is created on first write and is **not** part of the git repo — `git pull` will never overwrite it. Back it up alongside your other VPS data; if you ever rebuild the container, copy it back before starting `server-hub`.

---

## 4. Make it reachable

Pick one:

**A. Router port-forward (LAN / trusted network only).** Forward TCP `8642` on your router to `<container-ip>:8642`. Visit `http://<your-public-ip>:8642`. This is plain HTTP — fine on a trusted LAN, but don't expose the raw port to the open internet.

**B. Cloudflare Tunnel from the Zero Trust panel (recommended for the public internet, adds TLS later).** In the Cloudflare dashboard, add a public hostname (e.g. `hub.example.com`) routed to a tunnel whose service is `http://<container-ip>:8642` — no nginx involved, no public inbound port needed. The tunnel runs inside the container; Cloudflare terminates TLS at its edge and forwards to the container on `8642`.

---

## 5. Security notes

- `HUB_PASSWORD` lives in the systemd unit — restrict the file to root with `chmod 600 /etc/systemd/system/server-hub.service` (see §3) and set it to a long random value.
- The session cookie is `HttpOnly` + `SameSite=Lax` with a 30-day lifetime.
- Failed logins are locked out per IP after 5 attempts (60-second lockout).
- There is a single user: `HUB_USER` (default `admin`). Everyone signs in with the same credentials.
- When you add the tunnel (option B in §4), **keep `HUB_HOST=0.0.0.0`** — the tunnel connects from inside the container, so the server must listen on all interfaces, not just loopback.
- Behind a Cloudflare Tunnel (option B in §4), every external client appears to come from cloudflared's single source IP, so the per-IP login lockout degrades to a global 5-attempt cap: any attacker can fire 5 bad logins and lock out the admin (and everyone else) for 60 seconds. Treat it as a rate limiter, not a per-user guard, once the tunnel is enabled.

---

## 6. Update checklist

```bash
# from your workstation, in the project folder:
scp index.html categorize.js settings.js settings.html tests.html login.html server.py \
  root@<container-ip>:/srv/server-hub/

# in the container:
systemctl restart server-hub
```

Sessions are held in memory, so a restart signs everyone out — fine, they just sign in again.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `404` on `/login` | `server.py` not running | `systemctl status server-hub` — confirm the unit is active; `ss -ltnp \| grep 8642` |
| Server won't start | `HUB_PASSWORD` missing or empty | Check the unit: `systemctl cat server-hub` — `server.py` exits with "HUB_PASSWORD must be set" |
| Wrong password loops | `HUB_PASSWORD` / `HUB_USER` in the unit don't match what you type | `systemctl cat server-hub`, fix the `Environment=` lines, `systemctl restart server-hub` |
| "Too many attempts" lockout | 5 failed logins per IP | Wait 60 seconds, then try again |
| Sign-in works but dashboard has no stats bars | `/api/stats` returns `401` when not signed in; or non-Linux host has no `/proc` | Check you're signed in (cookie set). On a normal Debian LXC the bars fill in |
| Settings saved but gone after reload | You're still on `file://` — opaque origin blocks localStorage | Visit via `http://<host>:8642`, not by opening the file from disk. Verify with DevTools → Application → Local Storage — `server-hub:settings` should be present |
| Sessions drop on reboot | Sessions are in-memory | Restart is normal after reboot — sign in again (30-day cookie, so usually unnoticed) |
