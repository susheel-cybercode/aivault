# Deploy VulnLab to the Web

Three free hosting options. Pick one — Render is the easiest. Each takes ~5–15 min.

**Prerequisite for all three:** push this repo to GitHub.

---

## Step 0 — Push to GitHub (do this once)

1. Create a new **empty** repo at https://github.com/new
   - Name: `vulnlab`
   - Set to **Public** or **Private** (either works)
   - Do NOT add a README / .gitignore / license (we already have them)

2. From this folder on your machine:
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/vulnlab.git
   git branch -M main
   git push -u origin main
   ```

---

## Option A — Render (recommended, easiest)

Render auto-detects `render.yaml` and sets everything up.

1. Go to https://dashboard.render.com → **New +** → **Blueprint**
2. Select your `vulnlab` GitHub repo
3. Render reads `render.yaml` and lists the services — click **Apply**
4. Wait for the build (~3–5 min)

### Add your security secrets
In Render: open the `owasp-vulnerable-lab` web service → **Environment** → add:

| Key | Value |
|---|---|
| `VULNLAB_SAFE_MODE` | `1` (already in render.yaml) |
| `VULNLAB_GATE_USER` | `lab` (or any username) |
| `VULNLAB_GATE_PASS` | run `openssl rand -hex 24` locally, paste the output |
| `JWT_SECRET` | run `openssl rand -hex 32`, paste |
| `SESSION_SECRET` | run `openssl rand -hex 32`, paste |

5. Render redeploys. Visit your URL: `https://owasp-vulnerable-lab.onrender.com`
6. Browser prompts for Basic Auth — enter your gate user/pass. Done.

---

## Option B — fly.io

1. Install flyctl: https://fly.io/docs/flyctl/install/
2. Sign up / login:
   ```bash
   fly auth signup
   ```
3. From this folder:
   ```bash
   fly launch      # it sees fly.toml — accept the defaults
   ```
   - When prompted "Would you like to deploy now?" answer **N** so we can set secrets first.
4. Set your security secrets:
   ```bash
   fly secrets set VULNLAB_GATE_USER=lab \
                   VULNLAB_GATE_PASS=$(openssl rand -hex 24) \
                   JWT_SECRET=$(openssl rand -hex 32) \
                   SESSION_SECRET=$(openssl rand -hex 32)
   ```
5. Deploy:
   ```bash
   fly deploy
   ```
6. Open it:
   ```bash
   fly open
   ```
   Browser prompts for Basic Auth. Done.

---

## Option C — Split deploy (GitHub Pages static splash + Render API)

Use this if you want the pretty splash page on your own domain and the API on Render.

1. Deploy the **backend** on Render (Option A above). Note your URL, e.g. `https://owasp-vulnerable-lab.onrender.com`.
2. Edit `src/public/index.html` — find `window.VULNLAB_API` and set it to your Render URL.
3. Push the contents of `src/public/` to a `gh-pages` branch:
   ```bash
   git checkout -b gh-pages
   git rm -rf src tests .github 2>/dev/null
   mv src/public/* . && rm -rf src
   git add -A && git commit -m "Static splash" && git push origin gh-pages
   git checkout main
   ```
4. On GitHub: repo → **Settings** → **Pages** → Source: `gh-pages` branch / root.
5. Wait ~1 min. Visit `https://YOUR_USERNAME.github.io/vulnlab/` for the splash — it calls your Render backend.

---

## Verify it's safe

After deploy, run these against your live URL (replace `https://YOUR-URL`):

```bash
# Should require Basic Auth
curl -i https://YOUR-URL/

# Without creds → 401. Wrong creds → 401. Correct creds → 200.
curl -u lab:YOUR_GATE_PASS https://YOUR-URL/

# Should be sandboxed (not leak /etc/passwd, not eval code, not hit metadata)
curl -u lab:YOUR_GATE_PASS "https://YOUR-URL/broken-access/download?file=/etc/passwd"
curl -u lab:YOUR_GATE_PASS -X POST https://YOUR-URL/llm/llm02/execute \
  -H 'Content-Type: application/json' \
  -d '{"code":"process.env"}'
curl -u lab:YOUR_GATE_PASS "https://YOUR-URL/ssrf/fetch?url=http://169.254.169.254/"
```

Each should return a "SAFE MODE: ... blocked" message — not actual host data.

See [SECURITY.md](SECURITY.md) for the full hardening reference.
