# Auth Gateway

A secure, lightweight, and modern centralized authentication portal and forward-auth gateway designed for homelabs and self-hosted environments.

Auth Gateway provides zero-trust single sign-on (SSO) protection across multiple subdomains with mobile QR or 8-digit PIN code approval and an intelligent **auth-watchdog** that immediately locks client sessions upon revocation.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Configuration](#2-configuration)
  - [3. Set Approver Password](#3-set-approver-password)
  - [4. Docker Compose Deployment](#4-docker-compose-deployment)
- [Reverse Proxy Setup (Caddy)](#reverse-proxy-setup-caddy)
  - [Central Auth Portal Block](#central-auth-portal-block)
  - [Pattern A: Standard Protected Web App (SPA / Static)](#pattern-a-standard-protected-web-app-spa--static)
  - [Pattern B: App with Public Bypasses (e.g. Webhooks, Public Shares)](#pattern-b-app-with-public-bypasses-eg-webhooks-public-shares)
  - [Pattern C: App with WebSocket Connections (e.g. Uptime Kuma)](#pattern-c-app-with-websocket-connections-eg-uptime-kuma)
- [Adding and Configuring a New Service](#adding-and-configuring-a-new-service)
- [Configuration Reference (`config.json`)](#configuration-reference-configjson)
- [CLI Tools](#cli-tools)

---

## Features

- **Centralized Authentication**: One shared cookie across all subdomains (e.g., `*.example.com`).
- **Flexible Login Flows**:
  - **QR Code Scanning**: Scan a QR code on desktop using your authenticated mobile device to instantly approve the desktop session.
  - **PIN Code Authorization**: Enter an 8-digit PIN code on your mobile device to authorize a pending desktop login.
- **Instant Revocation Watchdog**: Automatically injects a lightweight `auth-watchdog.js` script into HTML responses. If a session is revoked or expires, client browsers (including SPAs and cached tabs) immediately lock and redirect to login without needing a page refresh.
- **Service Dashboard**: Displays a sleek launchpad with direct links to all configured services.
- **PWA & Shortcuts**: Installable Progressive Web App (PWA) with native mobile shortcuts (`Scan QR`, `Enter PIN`).
- **Zero Heavy Dependencies**: Pure Node.js + Express with no bulky database dependencies; sessions and configuration are kept in JSON storage.

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

Create your `data/config.json` based on [config.sample.json](file:///home/szymon/Projects/auth-gateway/config.sample.json):

```json
{
  "app": {
    "name": "Auth Gateway",
    "subtitle": "Scan the QR code with your mobile device to approve access.",
    "footerText": "auth.example.com"
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

> **Important**: Ensure `cookieDomain` matches your root domain prefixed with a dot (e.g., `.example.com`) so cookies are shared across all subdomains.

### 3. Set Approver Password

Run the CLI tool to set up the administrative approver password:

```bash
# Option A: Interactive setup (hashes with scrypt and saves to data/password.json):
npm run set-password
# Or via Docker:
docker compose run --rm auth-gateway node set-password.js

# Option B: Generate a hash directly to set via APPROVER_PASSWORD_HASH env var:
npm run hash-password "MySecretPassword"
# Or via Docker:
docker compose run --rm auth-gateway node hash-password.js "MySecretPassword"
```

This hashes the password using `scrypt` and either saves it to `data/password.json` or outputs `APPROVER_PASSWORD_HASH=...` for your environment.

### 4. Docker Compose Deployment

Create a `docker-compose.yml`:

```yaml
services:
  auth-gateway:
    image: auth-gateway:latest
    build: .
    container_name: auth-gateway
    restart: unless-stopped
    volumes:
      - gateway-data:/usr/src/app/data
    environment:
      - PORT=3000
      - DATA_DIR=/usr/src/app/data
    networks:
      - proxy-net

volumes:
  gateway-data:
    name: auth_gateway_data

networks:
  proxy-net:
    external: true
```

Start the container:

```bash
docker compose up -d
```

---

## Reverse Proxy Setup (Caddy)

Caddy provides automatic HTTPS and clean, readable configuration. Below are the recommended patterns for your `Caddyfile`.

### Central Auth Portal Block

Expose the Auth Gateway itself on its dedicated subdomain:

```caddy
auth.example.com {
	reverse_proxy auth-gateway:3000

	header {
		X-Frame-Options SAMEORIGIN
		X-Content-Type-Options nosniff
	}
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

	# 2. Handle 401 errors by redirecting to central auth login
	handle_errors {
		@unauthorized expression {http.error.status_code} == 401
		handle @unauthorized {
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	# 3. Security headers
	header {
		X-Frame-Options SAMEORIGIN
		X-Content-Type-Options nosniff
	}
}
```

---

### Pattern B: App with Public Bypasses (e.g. Webhooks, Public Shares)

Use this pattern when certain routes must bypass authentication while protecting the rest of the application (e.g., Pingvin Share public links, monitor push webhooks):

```caddy
share.example.com {
	# 1. Public bypasses (no forward_auth, directly to upstream container)
	handle /s/* {
		reverse_proxy share-app:3000
	}
	handle /api/shares* {
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

	# 3. Redirect unauthenticated requests to login
	handle_errors {
		@unauthorized expression {http.error.status_code} == 401
		handle @unauthorized {
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

	# 4. Redirect 401s to login
	handle_errors {
		@unauthorized expression {http.error.status_code} == 401
		handle @unauthorized {
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

Add an entry to the `"services"` array in your `data/config.json`:

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
- `disableService`: *(Optional)* If `true`, hides the service from the dashboard and blocks redirects/access.
- `disableAuth`: *(Optional)* If `true`, bypasses authentication verification for this service.

### Step 3: Add Service Block to Caddy

Add the site block to your `Caddyfile` on your reverse proxy host (choose Pattern A, B, or C above):

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

	handle_errors {
		@unauthorized expression {http.error.status_code} == 401
		handle @unauthorized {
			redir * https://auth.example.com/login?redirect={scheme}://{host}{uri} 302
		}
	}

	header {
		X-Frame-Options SAMEORIGIN
		X-Content-Type-Options nosniff
	}
}
```

### Step 4: Reload Services

1. **Restart Auth Gateway** to load the updated `config.json`:
   ```bash
   docker compose restart auth-gateway
   ```
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

| Section    | Key                  | Type    | Description                                                                    |
| ---------- | -------------------- | ------- | ------------------------------------------------------------------------------ |
| `app`      | `name`               | string  | Portal title displayed on login and dashboard pages.                           |
| `app`      | `subtitle`           | string  | Explanatory text beneath the portal title.                                     |
| `app`      | `footerText`         | string  | Text shown in the footer of all auth views.                                    |
| `server`   | `port`               | number  | Port Auth Gateway listens on inside the container (default: `3000`).           |
| `server`   | `host`               | string  | Listening interface (default: `0.0.0.0`).                                      |
| `server`   | `baseUrl`            | string  | Full public URL of the auth portal (e.g. `https://auth.example.com`).          |
| `session`  | `cookieDomain`       | string  | Root domain with leading dot for shared cookies (e.g. `.example.com`).         |
| `session`  | `authCookieName`     | string  | Name of the authentication cookie (default: `gateway_auth_token`).             |
| `session`  | `approverCookieName` | string  | Name of the mobile approver session cookie.                                    |
| `session`  | `sessionTtlHours`    | number  | Lifespan of an authenticated user session in hours (e.g. `72`).                |
| `session`  | `qrSessionTtlMs`     | number  | Lifespan of a pending QR approval request in milliseconds (default: `120000`). |
| `session`  | `approverTtlDays`    | number  | Lifespan of an approver session in days (e.g. `30`).                           |
| `services` | `id`                 | string  | Unique service identifier.                                                     |
| `services` | `name`               | string  | Title shown on the dashboard card.                                             |
| `services` | `subtitle`           | string  | Description shown on the dashboard card.                                       |
| `services` | `url`                | string  | Public HTTPS URL of the service.                                               |
| `services` | `upstream`           | string  | Internal backend container URL (e.g. `http://my-app:8080`).                    |
| `services` | `allowedRedirects`   | array   | List of URL patterns permitted for post-login redirection.                     |
| `services` | `disableService`     | boolean | Optional. When `true`, completely hides service from dashboard and disables redirects. |
| `services` | `disableAuth`        | boolean | Optional. When `true`, bypasses authentication verification for this service. |

---

## CLI Tools

Auth Gateway includes CLI helper scripts in the repository:

- **`npm run set-password`**: Interactive command to set or update the administrator / approver password. It prompts for confirmation, hashes the password using `scrypt`, updates `data/password.json`, and invalidates existing approver sessions.
  ```bash
  npm run set-password
  # Or: node set-password.js
  ```
- **`npm run hash-password <password>`**: Helper script to generate a salted `scrypt` password hash directly from the command line for use with the `APPROVER_PASSWORD_HASH` environment variable.
  ```bash
  npm run hash-password "MySecretPassword"
  # Or: node hash-password.js "MySecretPassword"
  ```

---

## License

MIT License. See [LICENSE](/LICENSE) for details.
