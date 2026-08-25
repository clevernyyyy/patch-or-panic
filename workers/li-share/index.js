// Cloudflare Worker: LinkedIn OAuth token exchange + post creation for Patch or Panic.
// Deploy: wrangler deploy
// Secret: wrangler secret put LI_CLIENT_SECRET

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

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    const json = h => ({ ...h, 'Content-Type': 'application/json' });

    try {
      const { code, redirect_uri, client_id, text } = await request.json();

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

      // Step 3: create the LinkedIn post via /rest/posts (accepts urn:li:person:{oidc_sub})
      const postResp = await fetch('https://api.linkedin.com/rest/posts', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json',
          'LinkedIn-Version': '202608',
          'X-Restli-Protocol-Version': '2.0.0',
        },
        body: JSON.stringify({
          author: authorUrn,
          lifecycleState: 'PUBLISHED',
          visibility: 'PUBLIC',
          commentary: text,
          distribution: {
            feedDistribution: 'MAIN_FEED',
            targetEntities: [],
            thirdPartyDistributionChannels: [],
          },
        }),
      });

      if (!postResp.ok) {
        const err = await postResp.text();
        throw new Error(`Post failed (${postResp.status}): ${err.slice(0, 200)}`);
      }

      return new Response(JSON.stringify({ ok: true }), { headers: json(corsHeaders(origin)) });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: json(corsHeaders(origin)),
      });
    }
  },
};
