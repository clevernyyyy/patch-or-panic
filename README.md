# Patch or Panic?

A CVE severity ranking game. Two vulnerabilities appear side by side — pick which one has the higher CVSS score. Get it right, keep the streak going. Get it wrong, game over.

Live at **[cve.wiki](https://cve.wiki)**

---

## What it is

- Single-page game served as static HTML from GitHub Pages
- CVE data pulled live from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) and cached for 8 hours
- Share your score to X/Twitter (URL intent) or LinkedIn (full OAuth post via Cloudflare Worker)
- Built and maintained by [Pixee](https://pixee.ai)

---

## Local development

### Requirements

- Node 20+ (uses `--env-file` natively — no dotenv package needed)
- A LinkedIn Developer App (see below)

### Setup

```bash
npm install
```

Create a `.env` file in the project root (gitignored):

```
LI_CLIENT_SECRET=<your LinkedIn app Primary Client Secret>
```

### Run

```bash
node --env-file=.env server.js
```

Game is at `http://localhost:3847`

The server:
- Serves `public/index.html` as the game
- Proxies CVE data from NVD with an 8-hour disk cache (`cve_cache.json`)
- Handles LinkedIn OAuth token exchange and posting at `POST /api/li-share`

---

## LinkedIn sharing

LinkedIn removed URL-based text pre-fill in 2018. To post pre-filled text, the app uses a full OAuth 2.0 flow:

1. User clicks **Share on LinkedIn** — a preview modal shows the exact post text
2. User clicks **Post to LinkedIn** — page redirects to LinkedIn consent screen
3. LinkedIn redirects back with an auth code
4. The auth code is exchanged for tokens server-side (local server in dev, Cloudflare Worker in production)
5. The member ID is extracted from the `id_token` JWT (`sub` claim)
6. A post is created via `POST https://api.linkedin.com/rest/posts` with `urn:li:person:{sub}` as the author
7. A success modal appears in-place (spinner while posting, transitions to confirmed)

### LinkedIn app setup

App: **patch-or-panic** (Client ID: `8623hnnvqqgfm4`) at [developers.linkedin.com](https://www.linkedin.com/developers/apps)

**Products required (both must be Added):**
- Share on LinkedIn → grants `w_member_social`
- Sign In with LinkedIn using OpenID Connect → grants `openid`, `profile`, `email`

**Auth → Redirect URLs:**
- `http://localhost:3847/`
- `https://cve.wiki/`

**Scopes requested:** `openid profile w_member_social`

### Post text

```
I scored {score} on Patch or Panic and ranked {n} CVEs correctly, the vulnerability severity game by @Pixee.

Can you beat me? https://cve.wiki/
```

`@Pixee` is sent to the API as `@[Pixee](urn:li:organization:96613129)` so LinkedIn links it to the Pixee company page.

---

## Production infrastructure

### GitHub Pages

`public/index.html` is deployed to GitHub Pages and served at `cve.wiki`. It is a fully self-contained single file — no build step.

Push to `main` to deploy.

### Cloudflare Worker

The LinkedIn OAuth flow requires a server-side secret exchange (the client secret must never be in the browser). In production this is handled by a Cloudflare Worker.

**Worker:** `pop-li-share`  
**URL:** `https://pop-li-share.aschaal1263.workers.dev`  
**Source:** `workers/li-share/index.js`

#### Deploy

```bash
cd workers/li-share
npx wrangler deploy
```

#### Set the LinkedIn client secret

```bash
npx wrangler secret put LI_CLIENT_SECRET --name pop-li-share
```

Paste the value from the LinkedIn app's Auth tab when prompted. The secret is stored encrypted in Cloudflare and never appears in the worker source.

#### How the worker is selected

The game detects at boot whether a local server is available (`GET /api/status`). If not (i.e. on cve.wiki), it uses `LI_WORKER_URL`. The worker handles CORS for `https://cve.wiki` and `http://localhost:3847`.

---

## Project structure

```
patch-or-panic/
├── public/
│   └── index.html        # The entire game (single file)
├── workers/
│   └── li-share/
│       ├── index.js      # Cloudflare Worker: LinkedIn OAuth + post
│       └── wrangler.toml # Worker config
├── server.js             # Local dev server (Express)
├── .env                  # Local secrets — gitignored
└── package.json
```

---

## Environment variables

| Variable | Where | Purpose |
|---|---|---|
| `LI_CLIENT_SECRET` | `.env` (dev) / Wrangler secret (prod) | LinkedIn app client secret for token exchange |
