# Setup — Cloudflare Access (secure login for public domains)

This guide wires [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/) in front of your self-hosted Server Hub homepage. **Auth happens at Cloudflare's edge** — every request to your domain is intercepted by Access before it ever reaches your VPS. The static `index.html` itself stays 100% static: no password in the file, no session cookie to forge, no offline brute-force surface.

This is the right architecture when you already run **`cloudflared` tunnel** (which you do), because Access policies can attach to any hostname exposed via your tunnel in one step.

```
┌─────────┐      ┌──────────────────┐      ┌─────────────────┐      ┌──────────┐
│ Browser │ ──► │ Cloudflare Edge  │ ──► │ cloudflared tunnel │ ──► │  VPS nginx │
│         │     │  Access SSO gate │      │  (no inbound port)│     │  index.html │
└─────────┘      └──────────────────┘      └─────────────────┘      └──────────┘
                  ▲ Requires OIDC email
                  │ Google / GitHub / OTP / Okta …
```

---

## 0. Prerequisites

- A Cloudflare account with the tunnel already up (`cloudflared tunnel` connected to your VPS, hostname proxied via Cloudflare).
- Server Hub deployed so `index.html` (and friends) is reachable on the internal hostname you set in `cloudflared`'s `ingress`. (See [`SETUP-deploy.md`](#) later — or just drop the files in your nginx web root.)
- The hostname must be a Cloudflare-proxied DNS record (orange-cloud). Tunnel-created records are proxied automatically — nothing to change.

---

## 1. Create an Access application for your homepage

1. Open **Cloudflare Zero Trust** → *Access* → *Applications* → **Add an application**.
2. Choose **Self-hosted**.
3. **Application configuration**
   - **Application name:** `Server Hub`
   - **Session Duration:** `24 hours` (or `720 hours` for "remember me" feel).
   - Leave *Force DNS rewrite* **off** for tunnel-proxied apps.
4. **Public hostname:** the domain serving Server Hub — e.g. `hub.example.com`.
   - **Path:** leave blank (covers `index.html`, `settings.html`, `tests.html`, `categorize.js`, `settings.js`).
5. **Identity providers:** enable whatever you trust — Google, GitHub, One-time PIN, cf-team domain, Okta, etc. **Recommended:** Google + One-time PIN as a fallback.
6. Click **Next**.

---

## 2. Define an "Include" policy (who may enter)

Cloudflare Access is **deny-by-default** — only matching policies grant access.

1. **Policy name:** `Just Me`
2. **Action:** `Allow`
3. **Session Duration:** inherit (or override).
4. **Rules** (any one match → granted):
   - **Include → Emails:** `you@example.com` (your address). Add every device's mailbox you sign in from.
   - **Or → Emails ending in:** `@your-google-workspace-domain.com` (if you have one).
   - **Or → Country:** your country (less precise, only if you want geo as a fallback).
5. Save → **Done**.

> **Tighten further (optional):** add a second policy `Block` with rule `IP ranges` outside your home/VPS IPs. Order matters; Access evaluates allow-before-block per request, so put `Block` after `Just Me`.

---

## 3. Wire `cloudflared` to serve the files

You don't need a public DNS record manually with tunnels — `cloudflared` config will create one. In your `config.yml`:

```yaml
# ~/.cloudflared/config.yml
tunnel: <your-tunnel-id>
credentials-file: /root/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: hub.example.com
    service: http://127.0.0.1:8080        # nginx serving server-hub/
    originRequest:
      noTLSVerify: true
  - service: http_status:404              # catch-all, MUST be last
```

A minimal `nginx` site so `127.0.0.1:8080` serves the homepage:

```nginx
server {
  listen 127.0.0.1:8080;
  server_name hub.example.com;
  root /var/www/server-hub;             # ← folder containing index.html
  index index.html;
  location / { try_files $uri /index.html; }
}
```

Then reload and restart the tunnel:

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart cloudflared
```

---

## 4. Verify

1. Visit `https://hub.example.com` in a private window.
2. You should be redirected to `https://hub.example.com/cdn-cgi/access/login/...` — the Cloudflare Access sign-in page.
3. Sign in with your email. The first time you'll receive a one-time PIN or go through the Google/GitHub flow.
4. After authentication, Server Hub loads. The Cloudflare-signed `CF_Authorization` cookie is now present and Access will not prompt again for `24 hours` (or whatever session duration you set).
5. Open DevTools → Network → the `cf-access-jwt-...` header is attached by the worker.

---

## 5. Optional — show the signed-in email on the homepage

The dashboard already pings `GET /api/me` to render a "signed in: <email>" chip.
This is purely cosmetic — the real auth is enforced at the edge — but it's a nice touch.

Add a tiny backend shim (any language) that reads the headers Access injects
and returns the email as JSON. Any of these work:

- **nginx + Lua** reads `$http_cf_access_client_email` and returns it.
- **`cf-access-validate`** middleware in Node/Express, Python Starlette, etc.
- **Caddy** with a `reverse_proxy` that adds `X-Email` from the header.

Minimal **nginx** shim (returns the email that Cloudflare injects as a header):

```nginx
location = /api/me {
  default_type application/json;
  if ($http_cf_access_client_email = "") { return 401 '{"error":"unauthenticated"}'; }
  return 200 '{"email":"$http_cf_access_client_email"}';
}
```

Cloudflare injects several headers after auth; `Cf-Access-Client-Email` is the
verified identity. **Never trust a raw client-supplied header** — only the names
Access itself sets are trustworthy.

If you don't want this nicety, simply leave `/api/me` unimplemented; the chip
stays hidden and the rest of the dashboard works.

---

## 6. Locking down other services via the same policy

Because every separate `service:` ingress entry shares the tunnel, you can add
Access applications for *each* self-hosted app on its own subdomain. Reusing
the `Just Me` policy takes ~30 seconds per app:

1. Add the hostname to `config.yml` ingress + reload `cloudflared`.
2. Access → Applications → Add → Self-hosted → new hostname.
3. Reuse existing `Just Me` policy by selecting "Add from existing".

Done — every service behind the tunnel is now reachable only after your
Google/GitHub/OTP identity is verified at the edge.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `403 Forbidden` even after login | Policy action is missing or set to `Service Auth` only. | Set policy action to `Allow`. |
| `CF_Authorization` cookie present but app still 401 | Origin validates CORS-Bypass-WAF on tunneled host — not needed with tunnels. | Disable origin-level auth; let Access be the only gate. |
| Login page loops infinitely | Browser blocking third-party cookies; the cookie domain is `.cloudflareaccess.com`. | Use a dedicated browser profile or allow third-party cookies on `*.cloudflareaccess.com`. |
| Requests fail CORS / status pings fail for the hub only | Status pings use `fetch(url, {mode:'no-cors'})`; Access cookies still attach automatically. | Add your other tunnels as separate Access apps; the cross-origin fetches will return opaque responses (which is what the up-check needs). For a windows-based ping endpoint that does require JSON, move those pings inside an Access app too or set `ping:false` in `SERVICES`. |
| CSS/JS for `/api/stats` blocked | Same Access gate applies to all paths under the hostname. | Log in once; cookie covers subsequent requests to `/api/stats`. |

---

## 8. What this does and does not protect

- ✅ **Prevents the public from viewing your homepage** — any unauthenticated request is intercepted at Cloudflare before reaching your VPS.
- ✅ **No static-password exposure** — there is no password in the file, nothing to offline-brute-force.
- ✅ **Per-device revocation** from one dashboard.
- ❌ Does **not** encrypt traffic between you and your VPS beyond TLS (Cloudflare adds TLS termination, origin is HTTP if you skip it — for stronger posture set up origin certs via `cloudflared` `originRequest.originServerName` + TLS).
- ❌ Does **not** hide the existence of `hub.example.com` from DNS scanners (Cloudflare proxied records resolve). If obscurity matters, add a `BLOCK` policy for unknown IPs and use the IP allow rule.

---

## Next steps

- Customize the homepage and settings: open `https://hub.example.com/settings.html`.
- Run the internal tests: `https://hub.example.com/tests.html` — true on a green line.
- Define more granular policies ("family" allow-list, time-of-day restrictions) in Access → Applications → {Server Hub} → Policies.