# Patch or Panic?

A CVE severity ranking game. Two vulnerabilities appear side by side — pick which one has the higher CVSS score. Get it right, keep the streak going. Get it wrong, game over.

Live at **[cve.wiki](https://cve.wiki)**

---

## What it is

- Single-page game served as static HTML from GitHub Pages
- CVE data pulled live from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) and cached for 8 hours
- Share your score to X, Bluesky, or LinkedIn — each share includes a generated score card image
- Built and maintained by [Pixee](https://pixee.ai)

---

## Running locally

### 1. Install dependencies

```bash
npm install
```

### 2. Create a `.env` file in the project root

```
LI_CLIENT_SECRET=<Primary Client Secret from the LinkedIn app>
```

Get the secret from the **patch-or-panic** app at [developers.linkedin.com](https://www.linkedin.com/developers/apps) → Auth → Application credentials.

### 3. Start the server

```bash
node --env-file=.env server.js
```

Open **http://localhost:3847**

The local server handles everything the Cloudflare Worker handles in production: CVE data proxying, LinkedIn OAuth, image upload, and posting. When the game detects `http://localhost:3847` is reachable (via `GET /api/status`), it routes LinkedIn share calls there instead of to the Worker.

> **Node version:** 20+ required. The `--env-file` flag is built into Node 20 — no dotenv package needed.

---

## How score card images work

When a game ends, the browser draws a 1200×630 JPEG score card on a hidden canvas (dark background, neon score number, game branding). The image flows three ways:

1. **LinkedIn** — the score card is shown in the preview modal before posting, then uploaded to LinkedIn's Images API so it appears inline in the feed (not just as a link)
2. **X and Bluesky** — the JPEG is stored in Workers KV and served at `https://cve.wiki/s/{token}`. Both platforms generate a link preview card from the `og:image` / `twitter:card` meta tags on that page
3. **Share page** — anyone who clicks the link lands on `cve.wiki/s/{token}`, a "Beat this score" page, and can jump into the game from there

Score images expire from KV after 7 days. If storage fails, shares fall back to text-only with a link to `cve.wiki`.

---

## LinkedIn sharing

LinkedIn doesn't support pre-filling share text via URL (removed in 2018), so the app uses a full OAuth 2.0 flow:

1. User clicks **Share on LinkedIn** → preview modal shows the score card and post text
2. User clicks **Post to LinkedIn** → browser redirects to LinkedIn's consent screen
3. LinkedIn redirects back with an auth code
4. The server exchanges the code for tokens (keeping the client secret out of the browser)
5. Member ID is pulled from the `id_token` JWT (`sub` claim)
6. Score card JPEG is uploaded to the LinkedIn Images API (`POST /rest/images?action=initializeUpload`)
7. Post is created via `POST /rest/posts` with the author URN and image URN attached
8. A confirmation modal replaces the spinner

### LinkedIn app settings

App: **patch-or-panic** (Client ID: `8623hnnvqqgfm4`) — [open in LinkedIn developer portal](https://www.linkedin.com/developers/apps)

**Products** (both must be added):
- **Share on LinkedIn** → grants `w_member_social`
- **Sign In with LinkedIn using OpenID Connect** → grants `openid profile email`

**Auth → Redirect URLs** (both must be listed):
- `http://localhost:3847/`
- `https://cve.wiki/`

**Scopes requested by the app:** `openid profile w_member_social`

### LinkedIn post text

```
I scored {score} on Patch or Panic and ranked {n} CVEs correctly,
the vulnerability severity game by @Pixee.

Can you beat me? https://cve.wiki/s/{token}
https://cve.wiki
```

`@Pixee` is passed to the API as `@[Pixee](urn:li:organization:96613129)` so it links to the Pixee company page.

---

## Deploying

### Game (GitHub Pages)

`public/index.html` is a fully self-contained single file — no build step. Push to `main` and GitHub Pages picks it up at `cve.wiki`.

### Cloudflare Worker

Source: `workers/li-share/`

The Worker handles LinkedIn OAuth, score image storage (Workers KV), and OG share pages — all the things that need a server secret or persistent storage.

**Worker URLs:**
- `https://pop-li-share.aschaal1263.workers.dev` — LinkedIn OAuth (`POST /`) and image storage (`POST /store`)
- `https://cve.wiki/s/*` → Worker route — OG share pages
- `https://cve.wiki/img/*` → Worker route — score card images

#### Deploying the worker

```bash
cd workers/li-share
npx wrangler deploy
```

This deploys the Worker and activates the `cve.wiki/s/*` and `cve.wiki/img/*` routes.

#### First-time setup (new environment only)

If setting up from scratch, do these before the first deploy:

**1. Set the LinkedIn client secret:**
```bash
npx wrangler secret put LI_CLIENT_SECRET --name pop-li-share
```

**2. Create the KV namespace for score images:**
```bash
npx wrangler kv namespace create SCORES
```
Copy the `id` from the output and paste it into `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "SCORES"
id = "<paste id here>"
```
The namespace is already created for this project (id: `3611f119249d41c897663557e9fd836e`), so this step is only needed if starting fresh.

#### Worker endpoints

| Method | Path | Served from | Purpose |
|---|---|---|---|
| `POST /` | `/` | workers.dev | LinkedIn OAuth token exchange + post creation |
| `POST /store` | `/store` | workers.dev | Save score card JPEG to KV; returns `cve.wiki/s/{token}` URL |
| `GET /s/{token}` | `/s/*` | cve.wiki | OG share page with score card meta tags |
| `GET /img/{token}` | `/img/*` | cve.wiki | Serve JPEG from KV |

---

## Analytics

All outbound links to `pixee.ai` include UTM parameters so traffic from the game is identifiable in analytics:

| Parameter | In-game links | Share page links |
|---|---|---|
| `utm_source` | `patch-or-panic` | `patch-or-panic` |
| `utm_medium` | `game` | `share-card` |
| `utm_campaign` | `cve-wiki` | `cve-wiki` |

"In-game links" are the "Powered by Pixee" footer links inside `index.html`. "Share page links" are the "by Pixee" link on `cve.wiki/s/{token}` pages.

---

## Project structure

```
patch-or-panic/
├── public/
│   └── index.html        # The entire game (single file, deployed to GitHub Pages)
├── workers/
│   └── li-share/
│       ├── index.js      # Cloudflare Worker: OAuth, KV storage, OG share pages
│       └── wrangler.toml # Worker config: routes, KV binding, workers_dev flag
├── server.js             # Local dev server (mirrors Worker behavior for LinkedIn flow)
├── .env                  # LI_CLIENT_SECRET — gitignored
└── package.json
```

---

## Environment variables

| Variable | Where | Purpose |
|---|---|---|
| `LI_CLIENT_SECRET` | `.env` (local) / Wrangler secret (production) | LinkedIn app client secret — used server-side only, never sent to the browser |
