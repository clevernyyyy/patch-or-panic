// Cloudflare Worker: LinkedIn OAuth + score image KV storage + OG share pages.
// Deploy: wrangler deploy
// Secrets: wrangler secret put LI_CLIENT_SECRET
// KV: wrangler kv namespace create SCORES  (add binding to wrangler.toml)

const ALLOWED_ORIGINS = ['https://cve.wiki', 'http://localhost:3847'];

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

function jsonResp(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const { pathname } = new URL(request.url);
    const workerOrigin = new URL(request.url).origin;

    // ── GET /img/{token} — serve stored JPEG ────────────────────────────────
    if (request.method === 'GET' && pathname.startsWith('/img/')) {
      const token = pathname.slice(5);
      const imgData = env.SCORES
        ? await env.SCORES.get(token, { type: 'arrayBuffer' })
        : null;
      if (!imgData) return new Response('Not found', { status: 404 });
      return new Response(imgData, {
        headers: { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=604800' },
      });
    }

    // ── GET /s/{token} — OG share page ──────────────────────────────────────
    if (request.method === 'GET' && pathname.startsWith('/s/')) {
      const token = pathname.slice(3);
      const metaRaw = env.SCORES ? await env.SCORES.get(token + ':meta') : null;
      if (!metaRaw) return new Response('Score not found', { status: 404, headers: { 'Content-Type': 'text/plain' } });
      const { score, streak } = JSON.parse(metaRaw);
      const imgUrl = `${workerOrigin}/img/${token}`;
      const s = Number(streak);
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Can you beat ${score} points? | Patch or Panic?</title>
<meta property="og:title" content="I scored ${score} on Patch or Panic">
<meta property="og:description" content="${s} CVE${s!==1?'s':''} ranked correctly. Can you beat ${score} points?">
<meta property="og:image" content="${imgUrl}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:url" content="${workerOrigin}/s/${token}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="I scored ${score} on Patch or Panic">
<meta name="twitter:description" content="${s} CVE${s!==1?'s':''} ranked correctly. Can you beat me?">
<meta name="twitter:image" content="${imgUrl}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@700;800&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#07090e;color:#dce8f5;font-family:'JetBrains Mono',monospace;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:32px;gap:28px;text-align:center}
img{max-width:min(640px,100%);border-radius:12px;border:1px solid rgba(0,212,255,0.15)}
.cta{display:inline-block;color:#07090e;background:#00d4ff;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:800;padding:14px 44px;border-radius:8px;letter-spacing:1px}
p{color:rgba(90,112,128,0.7);font-size:13px;font-family:'Inter',sans-serif}
</style>
</head>
<body>
<img src="${imgUrl}" alt="Score: ${score} on Patch or Panic">
<a class="cta" href="https://cve.wiki">Beat this score &rarr;</a>
<p>Patch or Panic? &middot; cve.wiki &middot; by Pixee</p>
</body>
</html>`;
      return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // ── POST /store — save score image to KV ────────────────────────────────
    if (pathname === '/store') {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders(origin) });
      }
      if (request.method === 'POST') {
        try {
          const { imageBase64, score, streak } = await request.json();
          const tokenBytes = crypto.getRandomValues(new Uint8Array(8));
          const token = Array.from(tokenBytes, b => b.toString(16).padStart(2, '0')).join('');
          const ttl = 7 * 24 * 60 * 60;
          const imgBytes = Uint8Array.from(atob(imageBase64), c => c.charCodeAt(0));
          await env.SCORES.put(token, imgBytes.buffer, { expirationTtl: ttl });
          await env.SCORES.put(token + ':meta', JSON.stringify({ score, streak }), { expirationTtl: ttl });
          return new Response(
            JSON.stringify({ token, url: `${workerOrigin}/s/${token}` }),
            { headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) } }
          );
        } catch (e) {
          return jsonResp({ error: e.message }, 500, corsHeaders(origin));
        }
      }
    }

    // ── POST / — LinkedIn OAuth token exchange + post ────────────────────────
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const { code, redirect_uri, client_id, text, imageBase64 } = await request.json();

      // Step 1: exchange auth code for tokens
      const tokenResp = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri,
          client_id,
          client_secret: env.LI_CLIENT_SECRET,
        }),
      });
      const tokenData = await tokenResp.json();
      const { access_token, id_token } = tokenData;
      if (!access_token) {
        throw new Error('No access_token — ' + (tokenData.error_description || JSON.stringify(tokenData).slice(0, 120)));
      }

      // Step 2: get member ID — from id_token (openid scope) or /v2/userinfo fallback
      let sub;
      if (id_token) {
        const b64 = id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(atob(b64));
        sub = String(payload.sub);
      } else {
        const uiResp = await fetch('https://api.linkedin.com/v2/userinfo', {
          headers: { Authorization: `Bearer ${access_token}`, 'LinkedIn-Version': '202608' },
        });
        const uiData = await uiResp.json();
        if (!uiData.sub) throw new Error('Cannot get member ID: ' + JSON.stringify(uiData).slice(0, 120));
        sub = String(uiData.sub);
      }
      const authorUrn = `urn:li:person:${sub}`;

      // Step 3: optionally upload score card image
      let imageUrn = null;
      if (imageBase64) {
        try {
          const liHeaders = {
            Authorization: `Bearer ${access_token}`,
            'Content-Type': 'application/json',
            'LinkedIn-Version': '202608',
            'X-Restli-Protocol-Version': '2.0.0',
          };
          const initResp = await fetch('https://api.linkedin.com/rest/images?action=initializeUpload', {
            method: 'POST',
            headers: liHeaders,
            body: JSON.stringify({ initializeUploadRequest: { owner: authorUrn } }),
          });
          const initData = await initResp.json();
          const uploadUrl = initData.value?.uploadUrl;
          imageUrn = initData.value?.image || null;
          if (uploadUrl && imageUrn) {
            const imgBytes = Uint8Array.from(atob(imageBase64), c => c.charCodeAt(0));
            await fetch(uploadUrl, {
              method: 'PUT',
              headers: { 'Content-Type': 'image/jpeg' },
              body: imgBytes,
            });
          } else {
            imageUrn = null;
          }
        } catch {
          imageUrn = null; // graceful degradation — post without image
        }
      }

      // Step 4: create the LinkedIn post
      const postBody = {
        author: authorUrn,
        lifecycleState: 'PUBLISHED',
        visibility: 'PUBLIC',
        commentary: text,
        distribution: {
          feedDistribution: 'MAIN_FEED',
          targetEntities: [],
          thirdPartyDistributionChannels: [],
        },
      };
      if (imageUrn) postBody.content = { media: { id: imageUrn } };

      const postResp = await fetch('https://api.linkedin.com/rest/posts', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json',
          'LinkedIn-Version': '202608',
          'X-Restli-Protocol-Version': '2.0.0',
        },
        body: JSON.stringify(postBody),
      });

      if (!postResp.ok) {
        const err = await postResp.text();
        throw new Error(`Post failed (${postResp.status}): ${err.slice(0, 200)}`);
      }

      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
      });
    } catch (e) {
      return jsonResp({ error: e.message }, 500, corsHeaders(origin));
    }
  },
};
