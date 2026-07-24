# Hosting VulnLab Safely

VulnLab is **intentionally vulnerable**. Hosting it on the public internet
without the precautions below can let visitors compromise the **host machine**
(RCE, file reads, cloud-metadata abuse), not just solve the in-app puzzles.

This guide explains the built-in safety controls and the deployment settings
required for public hosting.

---

## TL;DR — safe public-host settings

Set these env vars on every public deployment:

| Variable | Value | Why |
|---|---|---|
| `VULNLAB_SAFE_MODE` | `1` (default) | Sandboxes `eval`, `child_process`, path traversal, and link-local/loopback SSRF. Vulnerable endpoints still demo, but cannot touch the host. |
| `VULNLAB_GATE_USER` | e.g. `lab` | Locks the **entire** lab behind HTTP Basic Auth. |
| `VULNLAB_GATE_PASS` | strong secret | Pair for the gate above. |
| `NODE_ENV` | `production` | Enables secure session cookies. |
| `JWT_SECRET` / `SESSION_SECRET` | long random secrets | Replaces the insecure demo defaults in `src/app.js`. |

```bash
VULNLAB_SAFE_MODE=1 \
VULNLAB_GATE_USER=lab \
VULNLAB_GATE_PASS=$(openssl rand -hex 24) \
NODE_ENV=production \
JWT_SECRET=$(openssl rand -hex 32) \
SESSION_SECRET=$(openssl rand -hex 32) \
npm start
```

**Only set `VULNLAB_SAFE_MODE=0`** on a disposable, isolated host with no
cloud credentials, no other processes, and **never** on a public network.

---

## What `VULNLAB_SAFE_MODE=1` does

Implemented in [`src/utils/safe-guard.js`](src/utils/safe-guard.js) and wired
into the dangerous endpoints:

| Risk | Endpoint | Safe-mode behavior |
|---|---|---|
| Eval RCE | `POST /llm/llm02/execute`, `GET /vuln-components/eval-remote`, `POST /vuln-components/deserialize`, `POST /integrity-fails/deserialize`, `POST /api/b10/process-url` | Code is parsed for display but **not executed**. Response still shows the vuln shape + detected patterns. |
| Shell injection | `GET /injection/command-injection`, `POST /llm/llm07/plugin/execute` (`shell_exec`) | Command is parsed for display but **not spawned** on the host. |
| Path traversal | `GET /broken-access/download?file=/etc/passwd` | Reads are confined to the lab's `data/` directory; absolute/escape paths return 403. |
| SSRF → cloud metadata | `GET /ssrf/fetch`, `GET /api/b7/fetch-url`, `POST /llm/llm07/plugin/execute` (`curl`), `POST /api/b10/process-url` | Targets `169.254.169.254`, `127.0.0.1`, `localhost`, `::1`, `metadata.google.internal`, etc. are blocked. |

The intentionally vulnerable **logic** (SQLi, XSS, IDOR, JWT-none, weak crypto,
mass assignment, prompt-injection *simulation*, open redirect, etc.) still
functions so the lab remains educational in safe mode.

---

## Additional deployment hardening

### Run as non-root, no cloud creds
The Dockerfile already runs as a non-root `nodejs` user. Do **not** mount cloud
credentials, kubeconfig, or `.aws/` / `.gcloud/` / `~/.ssh` into the container.
SSRF is sandboxed, but defense-in-depth.

### Network isolation
Prefer running the lab on an isolated network/namespace with no outbound route
to internal services. Safe mode blocks the well-known metadata IPs but not
arbitrary internal hosts.

### Reverse proxy rate-limiting
Put a reverse proxy (Caddy, nginx, Cloudflare) in front with rate-limiting to
prevent brute-force of the Basic-Auth gate and DoS via large payloads.

### Rotate secrets
Generate fresh `JWT_SECRET`, `SESSION_SECRET`, and `VULNLAB_GATE_PASS` per
environment. Never reuse the demo defaults from `src/app.js` in any deployment.

### Disposable data
The SQLite DB in `data/vulnlab.db` is world-writable by design. Treat each
deployment as disposable — don't persist sensitive data into it.

---

## Reporting

This is an educational project. If you find a host-compromise path that the
safety guard misses (an `eval`/`exec`/path-traversal we didn't sandbox), please
open an issue so we can extend `src/utils/safe-guard.js`.

For the intentionally vulnerable endpoints — exploiting them **is** the point.
