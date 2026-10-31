# Auth Gateway

A secure, lightweight, and modern centralized authentication portal and forward-auth gateway designed for homelabs and self-hosted environments.

Auth Gateway provides zero-trust single sign-on (SSO) protection across multiple subdomains with mobile QR code or 8-digit PIN approval and an **auth-watchdog** script that immediately locks client sessions upon revocation.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Configuration](#2-configuration)
  - [3. Docker Compose Deployment](#3-docker-compose-deployment)
  - [4. Configure Approver Auth (FIDO Key or Password)](#4-configure-approver-auth-fido-key-or-password)
- [Reverse Proxy Setup (Caddy)](#reverse-proxy-setup-caddy)
  - [Shared Security Headers Snippet](#shared-security-headers-snippet)
  - [Central Auth Portal Block](#central-auth-portal-block)
  - [Pattern A: Standard Protected Web App (SPA / Static)](#pattern-a-standard-protected-web-app-spa--static)
  - [Pattern B: App with Public Bypasses (e.g. Webhooks, Public Shares)](#pattern-b-app-with-public-bypasses-eg-webhooks-public-shares)
  - [Pattern C: App with WebSocket Connections (e.g. Uptime Kuma)](#pattern-c-app-with-websocket-connections-eg-uptime-kuma)
  - [Pattern D: SPAs with Mixed Public & Protected Routes (e.g. ByteStash)](#pattern-d-spas-with-mixed-public--protected-routes-eg-bytestash)
- [Automated & API Access (Gateway Token)](#automated--api-access-gateway-token)
- [Health Check & Monitoring (`/auth/health`)](#health-check--monitoring-authhealth)
- [Session Management & Revocation Portal](#session-management--revocation-portal)
- [Adding and Configuring a New Service](#adding-and-configuring-a-new-service)
- [Configuration Reference (`config.json`)](#configuration-reference-configjson)
- [CLI Tools](#cli-tools)

---

## Features

- **Centralized Authentication**: One shared cookie across all subdomains (e.g., `*.example.com`).
- **Flexible Login Flows**:
  - **QR Code Scanning**: Scan a QR code on desktop using your authenticated mobile device to instantly approve the desktop session.
  - **PIN Authorization**: Enter an 8-digit PIN on your mobile device to authorize a pending desktop login.
- **Instant Revocation Watchdog**: Automatically injects a lightweight `auth-watchdog.js` script into HTML responses. If a session is revoked or expires, client browsers (including SPAs and cached tabs) immediately lock and redirect to login without needing a page refresh.
- **Dynamic SPA Navigation Guard**: Injects `auth-public-guard.js` into public SPA routes to dynamically intercept client-side transitions to protected routes (via Caddy `HEAD` probing) with zero path hardcoding.
- **Smart "Go Back" Navigation**: Preserves previous public or external referer (`&from=...`) so unauthenticated users who encounter a protected link can return to public content with a single click.
- **Session Management Dashboard**: Dedicated `/auth/sessions` management portal for approvers to monitor active sessions, device info, client IPs, user agents, and revoke individual sessions or all sessions simultaneously.
- **Hot Configuration Reloading**: Dynamic configuration file watcher automatically reloads `config.json` changes on disk in real time without restarting the container or losing active sessions.
- **Service Dashboard**: Displays a dashboard (`/portal`) with direct links to all configured services.
- **PWA & Shortcuts**: Installable Progressive Web App (PWA) with native mobile shortcuts (`Scan QR`, `Enter PIN`).
- **Hardware-backed FIDO2 / WebAuthn & Password 2FA**: First-class support for physical security keys (YubiKey, Titan, TouchID, FaceID, Windows Hello) with strict origin phishing protections, or scrypt-hashed passwords.
- **CSRF & Origin Isolation**: Built-in strict origin and Fetch-Metadata validation on all state-changing approver endpoints to prevent cross-site and cross-subdomain request forgery.
- **Strict Cookie & Subdomain Isolation**: User session cookies share the configured root domain (`.example.com`), whereas administrative approver session cookies are strictly host-only (`auth.example.com`) to prevent cross-subdomain cookie theft or subdomain takeover risks.
- **Rate Limiting & Brute-Force Protection**: Enforces rate limiting on QR session initialization (`/auth/init`) with dynamic client countdowns, and progressive lockout protections on password attempts (`/auth/login`).
- **Memory-Safe HTML Streaming**: Reverse proxy incorporates a buffer cap to prevent memory exhaustion / denial-of-service when proxying large upstream HTML responses.
- **Zero External Databases**: Lightweight Node.js + Express with JSON storage for sessions and configuration.

---

## How It Works

```
                     ┌──────────────────────────────────────┐
                     │          Browser / Client            │
                     └──────────────────┬───────────────────┘
                                        │ Requests https://tools.example.com
                                        ▼
                     ┌──────────────────────────────────────┐
                     │             Caddy Proxy              │
                     └──────┬────────────────────────┬──────┘
                            │                        │
       1. forward_auth      │                        │ 3. reverse_proxy
   (checks cookie validity) │                        │ (HTML injected with
                            ▼                        │  auth-watchdog.js)
                 ┌────────────────────┐              ▼
                 │    Auth Gateway    │◄─── fetches ─┤
                 │    (port 3000)     │    upstream  │
                 └────────────────────┘              ▼
                                            ┌─────────────────┐
                                            │ Downstream App  │
                                            │ (e.g. IT-Tools) │
                                            └─────────────────┘
```

1. **Forward Auth Verification**: Caddy checks incoming requests against `http://auth-gateway:3000/auth/verify`.
2. **Unauthorized Handling**: If the session cookie is missing or invalid, Caddy responds with `401 Unauthorized` and immediately redirects the user to `https://auth.example.com/login?redirect=...`.
3. **Injected Reverse Proxy**: For protected HTML pages, Caddy routes through `auth-gateway`, which proxies to the upstream backend container while injecting `auth-watchdog.js`.
4. **Real-time Watchdog**: The client browser periodically validates the session. If you revoke the session from the Auth Portal, all active tabs across all services lock within seconds.

---

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose installed.
- A reverse proxy (e.g. **Caddy**) attached to a shared Docker bridge network (e.g., `proxy-net`).
- A domain with wildcard or individual DNS records pointing to your server (e.g. `auth.example.com`, `tools.example.com`).

### 2. Configuration

Create your `config.json` based on [config.sample.json](/config.sample.json):

```json
{
  "app": {
    "name": "Auth Gateway",
    "subtitle": "Scan the QR code or enter the PIN on the authenticated device to approve access.",
    "footerText": "auth.example.com",
    "showRestricted": false
  },
  "server": {
    "port": 3000,
    "host": "0.0.0.0",
    "baseUrl": "https://auth.example.com"
  },
  "session": {
    "cookieDomain": ".example.com",
    "authCookieName": "gateway_auth_token",
    "approverCookieName": "gateway_approver_session",
    "sessionTtlHours": 72,
    "qrSessionTtlMs": 120000,
    "approverTtlDays": 30
  },
  "services": []
}
```

> **Important**: Ensure `cookieDomain` matches your root domain prefixed with a dot (e.g., `.example.com`) so user authentication cookies (`gateway_auth_token`) are shared across all subdomains. The administrative approver cookie (`gateway_approver_session`) always remains strictly **host-only** (locked to `auth.example.com`) for security.

Create an `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Set a secret `GATEWAY_TOKEN` for automated scripts, browser extensions, or API access:

```env
GATEWAY_TOKEN=your-random-secret-token-here
```

### 3. Docker Compose Deployment

Create a `docker-compose.yml`:

```yaml
services:
  auth-gateway:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: auth-gateway
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - gateway-data:/usr/src/app/data
      - ./config.json:/usr/src/app/config.json:ro
    environment:
      - PORT=3000
      - DATA_DIR=/usr/src/app/data
      - CONFIG_PATH=/usr/src/app/config.json
    networks:
      - proxy-net

volumes:
  gateway-data:
    external: true
    name: gateway-data

networks:
  proxy-net:
    external: true
    name: proxy-net
```

Start the container:

```bash
docker compose up -d
```

### 4. Configure Approver Auth (FIDO Key or Password)

Auth Gateway supports two mutually exclusive approver authentication methods. Configure your preferred method:

#### Option A: FIDO2 Hardware Security Key (Recommended)
Register a physical hardware key (YubiKey, Google Titan) or biometric passkey via a single-use direct link in the terminal:

```bash
docker compose exec -it auth-gateway node set-fido.js
# Or locally: npm run set-fido
```
This prints a 5-minute single-use link. Open the link in your browser, touch your key, and the terminal activates FIDO mode immediately.

#### Option B: Master Password
Set an administrative approver password (salted with `scrypt` and saved to `data/password.json`):

```bash
docker compose exec -it auth-gateway node set-password.js
# Or locally: npm run set-password
```

#### Option C: Switch Methods or Manage Keys Anytime
Toggle between Password and FIDO mode or manage keys at any time:

```bash
docker compose exec -it auth-gateway node set-auth-method.js
# Or locally: npm run set-auth-method
```

---

## Reverse Proxy Setup (Caddy)

Caddy provides automatic HTTPS and clean, readable configuration. Below are the recommended patterns for your `Caddyfile`.

### Shared Security Headers Snippet

Define a reusable snippet in your `Caddyfile` that sets standard security headers and strips internal authentication headers so untrusted external clients cannot spoof them:

```caddy
(security_headers) {
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options nosniff
		X-Frame-Options SAMEORIGIN
		Referrer-Policy "strict-origin-when-cross-origin"
		X-Robots-Tag "noindex, nofollow, noarchive"
	}
	# Prevent untrusted clients from spoofing internal authentication and proxy headers
	request_header -X-Auth-Status
	request_header -X-Auth-Role
	request_header -X-Auth-User
	request_header -X-Forwarded-Method
	request_header -X-Service-Host
}
```

---

### Central Auth Portal Block

Expose the Auth Gateway itself on its dedicated subdomain:

```caddy
auth.example.com {
	import security_headers
	reverse_proxy auth-gateway:3000
}
```

---

### Pattern A: Standard Protected Web App (SPA / Static)

Use this pattern for standard web applications (e.g. IT-Tools, personal dashboards, wikis):

```caddy
tools.example.com {
	# 1. Forward Auth + Watchdog injection via auth-gateway
	handle {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy auth-gateway:3000
	}

	# 2. Intelligent handling of 401 errors (JSON for API, redirect with Referer for browser)
	handle_errors {
		@api expression {http.error.status_code} == 401 && path('/api/*')
		handle @api {
			header Content-Type "application/json"
			respond `{"statusCode":401,"message":"Authentication required"}` 401
		}

		handle {
			@withReferer header Referer *
			redir @withReferer https://auth.example.com/login?redirect={scheme}://{host}{uri}&from={header.Referer} 302
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	import security_headers
}
```

---

### Pattern B: App with Public Bypasses (e.g. Webhooks, Public Shares)

Use this pattern when certain routes must bypass authentication while protecting the rest of the application (e.g., Pingvin Share public links, monitor push webhooks):

```caddy
share.example.com {
	# 1. Public bypasses (read-only downloads directly to upstream container)
	handle /s/* {
		reverse_proxy share-app:3000
	}
	@publicShareApi {
		method GET HEAD
		path /api/shares/*
	}
	handle @publicShareApi {
		reverse_proxy share-app:3000
	}
	handle /favicon.ico {
		reverse_proxy share-app:3000
	}

	# 2. Protected routes (requires forward auth & routes through auth-gateway)
	handle {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy auth-gateway:3000
	}

	# 3. Intelligent handling of 401 errors
	handle_errors {
		@api expression {http.error.status_code} == 401 && path('/api/*')
		handle @api {
			header Content-Type "application/json"
			respond `{"statusCode":401,"message":"Authentication required"}` 401
		}

		handle {
			@withReferer header Referer *
			redir @withReferer https://auth.example.com/login?redirect={scheme}://{host}{uri}&from={header.Referer} 302
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	import security_headers
}
```

---

### Pattern C: App with WebSocket Connections (e.g. Uptime Kuma)

For applications that use WebSockets, forward auth should verify the session, but the WebSocket upgrade should proxy **directly** to the backend container to avoid overhead or buffering:

```caddy
uptime.example.com {
	# 1. Public webhooks / push monitors (bypasses auth completely)
	handle /api/push/* {
		reverse_proxy kuma:3001
	}

	# 2. WebSocket connections (forward_auth check, then direct proxy to container)
	handle /socket.io/* {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			header_up -Upgrade
			header_up Connection close
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy kuma:3001
	}

	# 3. Protected web UI (forward auth + auth-watchdog injection)
	handle {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy auth-gateway:3000
	}

	# 4. Intelligent handling of 401 errors
	handle_errors {
		@api expression {http.error.status_code} == 401 && path('/api/*')
		handle @api {
			header Content-Type "application/json"
			respond `{"statusCode":401,"message":"Authentication required"}` 401
		}

		handle {
			@withReferer header Referer *
			redir @withReferer https://auth.example.com/login?redirect={scheme}://{host}{uri}&from={header.Referer} 302
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	import security_headers
}
```

---

### Pattern D: SPAs with Mixed Public & Protected Routes (e.g. ByteStash)

When protecting **Single Page Applications (SPAs)** (built with React, Vue, Next.js, etc.) that feature both **public pages** (e.g., `/public/snippets`, `/s/*`, shared URLs) and **protected pages** (e.g., `/`, `/login`, `/admin`), client-side routing presents a challenge:

- When an unauthenticated visitor opens a public page, the SPA runs in browser memory.
- If the visitor clicks an internal link (e.g., "Login" or the app dashboard), client-side routers (`history.pushState`) switch the view locally **without sending an HTTP GET request to Caddy**.
- Without handling, the unauthenticated visitor would see the app's internal login screen or a broken state rather than being redirected to central Auth Gateway login.

#### The Solution: Dynamic Caddy Navigation Guard (`auth-public-guard.js`)

Auth Gateway provides an automated public navigation guard with **zero hardcoded paths**:

1. **Proxy Public HTML through Auth Gateway**: Public HTML routes in Caddy are routed to `reverse_proxy auth-gateway:3000` with the `header_up X-Auth-Status "public"` header.
2. **Automated Guard Injection**: Auth Gateway forwards the public request to the upstream app without requiring a session and automatically injects `/auth/assets/auth-public-guard.js` into the HTML response. (If the user already has a valid session, the full `auth-watchdog.js` is injected instead).
3. **Dynamic Verification with Caddy**: The guard script hooks `history.pushState`, `history.replaceState`, link hover (`mouseover`), and `click`. It dynamically verifies target URLs with Caddy using lightweight `HEAD` requests (`fetch(url, { method: 'HEAD', redirect: 'manual' })`):
   - **Public route (`200 OK`)**: Caddy allows it — the SPA transition proceeds client-side seamlessly with no page reload.
   - **Protected route (`302 Found` / `401`)**: Caddy intercepts it — the guard immediately forces a full browser navigation (`window.location.href = url`), allowing Caddy's `forward_auth` to redirect the user to `https://auth.example.com/login?redirect=...`.
4. **Pre-caching on Hover**: When the user hovers over a link, the check runs in the background (< 5ms), enabling instant synchronous redirects when clicked.
5. **No Route Hardcoding**: Caddy's `Caddyfile` remains the single source of truth for which routes are public and which are protected.

#### Caddyfile Example:

```caddy
stash.example.com {
	# 1. Public static assets & workers (direct to upstream container for max performance)
	handle /assets/* {
		reverse_proxy bytestash:5000
	}
	handle /monacoeditorwork/* {
		reverse_proxy bytestash:5000
	}
	handle /favicon.ico {
		reverse_proxy bytestash:5000
	}
	handle /manifest.json {
		reverse_proxy bytestash:5000
	}

	# 2. Public HTML routes (proxied through auth-gateway with X-Auth-Status for guard injection)
	handle /public/snippets* {
		reverse_proxy auth-gateway:3000 {
			header_up X-Auth-Status "public"
		}
	}
	handle /s/* {
		reverse_proxy auth-gateway:3000 {
			header_up X-Auth-Status "public"
		}
	}

	# 3. Public APIs needed by public views & client bootstrapping
	handle /api/public/* {
		reverse_proxy bytestash:5000
	}
	handle /api/share/* {
		reverse_proxy bytestash:5000
	}
	handle /api/auth/config {
		reverse_proxy bytestash:5000
	}

	# 4. Protected REST APIs (checked via forward_auth, direct to upstream)
	handle /api/* {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy bytestash:5000
	}

	# 5. Protected Web UI routes (checked via forward_auth, injected with auth-watchdog)
	handle {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy auth-gateway:3000
	}

	# 6. Redirect 401s to central login
	handle_errors {
		@api expression {http.error.status_code} == 401 && path('/api/*')
		handle @api {
			header Content-Type "application/json"
			respond `{"statusCode":401,"message":"Authentication required"}` 401
		}

		handle {
			@withReferer header Referer *
			redir @withReferer https://auth.example.com/login?redirect={scheme}://{host}{uri}&from={header.Referer} 302
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	header {
		X-Frame-Options SAMEORIGIN
		X-Content-Type-Options nosniff
	}
}
```

---

## Automated & API Access (Gateway Token)

Auth Gateway supports automated, headless, and third-party client access (such as browser extensions, CLI tools, cron scripts, and mobile apps) without requiring interactive browser logins or cookie manipulation.

### Configuring the Token

1. Define `GATEWAY_TOKEN` in `.env`:
   ```env
   GATEWAY_TOKEN=your-random-secret-token-here
   ```
2. Docker Compose automatically passes `.env` to `auth-gateway`.

### Passing the Token in Requests

Any request sent with a matching token is immediately authenticated by Auth Gateway (`200 OK`, `X-Auth-Role: api_token`) and bypasses HTML watchdog injection:

- **Custom Headers**:
  ```http
  X-Gateway-Token: your-random-secret-token-here
  ```
  or
  ```http
  X-Auth-Token: your-random-secret-token-here
  ```
- **Bearer Authorization**:
  ```http
  Authorization: Bearer your-random-secret-token-here
  ```

### Example Usage

**cURL**:

```bash
curl -H "X-Gateway-Token: your-random-secret-token-here" https://myapp.example.com/api/data
```

---

## Health Check & Monitoring (`/auth/health`)

Auth Gateway provides an endpoint at `/auth/health` designed for homelab uptime monitors (e.g. Uptime Kuma, Beszel) and administrative status checks.

### 1. Unprivileged Public Monitoring
When requested without credentials, the endpoint returns a minimal status payload to verify gateway availability without disclosing internal infrastructure details:

```bash
curl -s https://auth.example.com/auth/health
```

```json
{
  "status": "ok",
  "timestamp": "2026-10-31T10:00:00.000Z"
}
```

### 2. Privileged Metrics & Service Status
When requested with your **`GATEWAY_TOKEN`** (or by an authenticated approver browser), the endpoint exposes full runtime statistics, active user sessions, approver sessions, memory usage, and configured service statuses:

```bash
# Using X-Gateway-Token
curl -s -H "X-Gateway-Token: your-random-secret-token-here" https://auth.example.com/auth/health

# Or using Bearer Authorization
curl -s -H "Authorization: Bearer your-random-secret-token-here" https://auth.example.com/auth/health
```

```json
{
  "status": "ok",
  "timestamp": "2026-10-31T10:00:00.000Z",
  "uptime": 3600.5,
  "metrics": {
    "activeSessions": 8,
    "approverSessions": 2,
    "pendingLogins": 0,
    "memoryRssMb": 71.2
  },
  "services": [
    {
      "id": "tools",
      "name": "IT Tools",
      "url": "https://tools.example.com",
      "disableService": false,
      "disableAuth": false
    }
  ]
}
```

---

## Session Management & Revocation Portal

Authenticated mobile approvers have access to an administrative session management portal at `/auth/sessions` (accessible from the mobile approver menu):

- **Live Device Inspection**: View every active desktop and client session across all subdomains, including IP address, browser/device user agent, and creation/expiration timestamps.
- **Granular Revocation**: Revoke an individual session with one click.
- **Global Emergency Revocation**: Click **Revoke All Sessions** to immediately invalidate every active session in the homelab while maintaining your current approver credentials.
- **Zero-Latency Client Lock**: Because `auth-watchdog.js` is active in every authenticated browser tab, revoked clients are locked and returned to the login portal within seconds via WebSockets and heartbeat polling.

---

## Adding and Configuring a New Service

Follow these 5 steps whenever you add a new self-hosted service behind Auth Gateway:

### Step 1: Attach Service to Shared Docker Network

Make sure the new service's container is on the same Docker network as Caddy and Auth Gateway (e.g., `proxy-net`):

```yaml
# In the new service's docker-compose.yml:
services:
  my-app:
    image: my-service:latest
    container_name: my-app
    restart: unless-stopped
    networks:
      - proxy-net

networks:
  proxy-net:
    external: true
```

### Step 2: Register Service in `config.json`

Add an entry to the `"services"` array in your `config.json`:

```json
{
  "id": "myapp",
  "name": "My Application",
  "subtitle": "Description shown on the Auth Portal dashboard",
  "url": "https://myapp.example.com",
  "upstream": "http://my-app:8080",
  "allowedRedirects": ["https://myapp.example.com*"],
  "disableService": false,
  "disableAuth": false
}
```

- `id`: Unique identifier for the service.
- `name`: Display name shown on the Auth Portal dashboard card.
- `subtitle`: Subtitle description for the service card.
- `url`: Public URL of your service.
- `upstream`: Internal Docker URL and port where the app container is listening.
- `allowedRedirects`: Allowed redirect URL patterns after successful authentication.
- `disableService`: _(Optional)_ If `true`, hides the service from the dashboard and blocks redirects/access.
- `disableAuth`: _(Optional)_ If `true`, bypasses authentication verification for this service.

### Step 3: Add Service Block to Caddy

Add the site block to your `Caddyfile` on your reverse proxy host (choose Pattern A, B, C, or D above):

```caddy
myapp.example.com {
	handle {
		forward_auth auth-gateway:3000 {
			uri /auth/verify
			copy_headers X-Auth-Status X-Auth-Role
			@unauthorized status 401
			handle_response @unauthorized {
				error 401
			}
		}
		reverse_proxy auth-gateway:3000
	}

	# Intelligent handling of 401 errors
	handle_errors {
		@api expression {http.error.status_code} == 401 && path('/api/*')
		handle @api {
			header Content-Type "application/json"
			respond `{"statusCode":401,"message":"Authentication required"}` 401
		}

		handle {
			@withReferer header Referer *
			redir @withReferer https://auth.example.com/login?redirect={scheme}://{host}{uri}&from={header.Referer} 302
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	import security_headers
}
```

### Step 4: Reload Services

1. **Auth Gateway (Automatic Hot-Reload)**:
   Auth Gateway watches `config.json` via file watching and hot-reloads service changes automatically within ~1.5 seconds without container restart or dropping active user sessions.
   *(Optional manual restart if preferred: `./reload-config.sh` or `docker compose restart auth-gateway`)*.

2. **Reload Caddy**:
   ```bash
   caddy reload --config /etc/caddy/Caddyfile
   # Or inside Docker:
   docker exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

### Step 5: Verify the Setup

1. **Test unauthenticated access**: Visit `https://myapp.example.com` in a private browsing window. You should be redirected to `https://auth.example.com/login?redirect=https://myapp.example.com/`.
2. **Test login & dashboard**: Log in via QR code or 8-digit PIN authorization on your mobile device. You should see "My Application" listed on the dashboard and clicking it should open the app without re-prompting for credentials.
3. **Test watchdog logout**: With the app open in one tab, open `https://auth.example.com` in another tab and click **Log Out** (or revoke the session). The app tab should lock and redirect to the login screen within seconds.

---

## Configuration Reference (`config.json`)

| Section    | Key                  | Type    | Description                                                                                                                   |
| ---------- | -------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `app`      | `name`               | string  | Portal title displayed on login and dashboard pages.                                                                          |
| `app`      | `subtitle`           | string  | Explanatory text beneath the portal title.                                                                                    |
| `app`      | `footerText`         | string  | Text shown in the footer of all auth views.                                                                                                |
| `app`      | `showRestricted`     | boolean | Optional. Whether services that the session is not authorized to access are displayed on the dashboard (`true`) or hidden (`false`, default: `false`). |
| `app`      | `gatewayToken`       | string  | Optional. Alternative to `GATEWAY_TOKEN` env var for automated API tokens.                                                                 |
| `server`   | `port`               | number  | Port Auth Gateway listens on inside the container (default: `3000`).                                                                       |
| `server`   | `host`               | string  | Listening interface (default: `0.0.0.0`).                                                                                                  |
| `server`   | `baseUrl`            | string  | Full public URL of the auth portal (e.g. `https://auth.example.com`).                                                                      |
| `session`  | `cookieDomain`       | string  | Root domain with leading dot for shared cookies (e.g. `.example.com`).                                                                     |
| `session`  | `authCookieName`     | string  | Name of the authentication cookie (default: `gateway_auth_token`).                                                                         |
| `session`  | `approverCookieName` | string  | Name of the mobile approver session cookie.                                                                                                |
| `session`  | `sessionTtlHours`    | number  | Lifespan of an authenticated user session in hours (e.g. `72`).                                                                            |
| `session`  | `qrSessionTtlMs`     | number  | Lifespan of a pending QR approval request in milliseconds (default: `120000`).                                                             |
| `session`  | `approverTtlDays`    | number  | Lifespan of an approver session in days (e.g. `30`).                                                                                       |
| `services` | `id`                 | string  | Unique service identifier.                                                                                                                 |
| `services` | `name`               | string  | Title shown on the dashboard card.                                                                                                         |
| `services` | `subtitle`           | string  | Description shown on the dashboard card.                                                                                                   |
| `services` | `url`                | string  | Public HTTPS URL of the service.                                                                                                           |
| `services` | `upstream`           | string  | Internal backend container URL (e.g. `http://my-app:8080`).                                                                                |
| `services` | `allowedRedirects`   | array   | List of URL patterns permitted for post-login redirection (e.g. `["https://myapp.example.com*"]`). Wildcards (`*`) supported.              |
| `services` | `disableService`     | boolean | Optional. When `true`, completely hides service from dashboard and disables redirects.                                                     |
| `services` | `disableAuth`        | boolean | Optional. When `true`, bypasses authentication verification for this service.                                                              |

---

## CLI Tools

Auth Gateway includes CLI helper scripts in the repository:

- **`npm run set-password`**: Interactive command to set or update the administrator / approver password. It prompts for confirmation, hashes the password using `scrypt`, updates `data/password.json`, and asks whether you want to log out every active session (or keep existing sessions intact).
  ```bash
  npm run set-password
  # Or: node set-password.js
  # Or with flags: node set-password.js --keep-sessions / --logout-all
  ```
- **`npm run logout-sessions`**: Interactive command to selectively log out active sessions. It prompts whether to log out only user sessions, approver sessions, or both (every session).
  ```bash
  npm run logout-sessions
  # Or: node logout-sessions.js
  # Or with flags: node logout-sessions.js --user / --approver / --both
  ```
- **`npm run set-auth-method`**: Interactive command to choose the active approver login method (**either Password OR FIDO Security Key**). If FIDO is selected without registered keys, it automatically starts a secure one-time enrollment link session.
  ```bash
  npm run set-auth-method
  # Or: node set-auth-method.js
  ```
- **`npm run set-fido`**: CLI tool to manage FIDO2 security keys: register new keys via single-use direct link, list existing keys, or revoke/delete keys with automatic password fallback protection.
  ```bash
  npm run set-fido
  # Or: node set-fido.js
  # Or with flags: node set-fido.js --add / --delete <num|id> / --list
  ```
- **`npm run hash-password <password>`**: Helper script to generate a salted `scrypt` password hash directly from the command line for use with the `APPROVER_PASSWORD_HASH` environment variable.
  ```bash
  npm run hash-password "MySecretPassword"
  # Or: node hash-password.js "MySecretPassword"
  ```
- **`./reload-config.sh`**: Reloads configuration changes by cleanly restarting the Docker container while preserving all active sessions.
  ```bash
  ./reload-config.sh
  ```

---

## License

MIT License. See [LICENSE](/LICENSE) for details.
