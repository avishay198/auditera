/**
 * Auditera Cloudflare Worker
 * ─────────────────────────
 * Endpoints:
 *   POST /validate  — אימות רישיון
 *   POST /register  — העברת הרשמה ל-Make → Airtable
 *
 * Environment variables (הגדר ב-Cloudflare Dashboard → Settings → Variables):
 *   LIC_SECRET        — המפתח הסודי לאימות טוקן רישיון
 *   MAKE_WEBHOOK_URL  — ה-URL הסודי של Make webhook
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env) {
    // OPTIONS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);

    // ── POST /validate — אימות רישיון ─────────────────────────
    if (request.method === 'POST' && url.pathname === '/validate') {
      return handleValidate(request, env);
    }

    // ── POST /register — העברה ל-Make ─────────────────────────
    if (request.method === 'POST' && url.pathname === '/register') {
      return handleRegister(request, env);
    }

    return new Response('Not found', { status: 404, headers: CORS });
  }
};

// ══════════════════════════════════════════════════════════════
// /validate — אימות רישיון HMAC-SHA256
// ══════════════════════════════════════════════════════════════
async function handleValidate(request, env) {
  try {
    const { token, email } = await request.json();
    if (!token || !email) {
      return json({ valid: false, error: 'missing_params' }, 400);
    }

    const secret = env.LIC_SECRET;
    if (!secret) {
      return json({ valid: false, error: 'server_config' }, 500);
    }

    // פענח טוקן: base64(plan|quota|expiry|hmac)
    let decoded;
    try {
      decoded = atob(token.trim());
    } catch {
      return json({ valid: false, error: 'invalid_token' });
    }

    const lastPipe = decoded.lastIndexOf('|');
    if (lastPipe === -1) return json({ valid: false, error: 'invalid_token' });

    const payload = decoded.slice(0, lastPipe);
    const tokenHmac = decoded.slice(lastPipe + 1);
    const parts = payload.split('|');
    if (parts.length < 4) return json({ valid: false, error: 'invalid_token' });

    const [plan, quota, expiry, tokenEmail] = parts;

    // בדוק מייל
    if (tokenEmail.toLowerCase() !== email.toLowerCase().trim()) {
      return json({ valid: false, error: 'email_mismatch' });
    }

    // בדוק תאריך פקיעה (פורמט YYYY-MM)
    const [yr, mo] = expiry.split('-').map(Number);
    if (isNaN(yr) || isNaN(mo) || new Date() >= new Date(yr, mo, 1)) {
      return json({ valid: false, error: 'expired' });
    }

    // בדוק HMAC
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const expectedHmac = Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    if (expectedHmac !== tokenHmac) {
      return json({ valid: false, error: 'invalid_signature' });
    }

    return json({ valid: true, plan, quota: Number(quota), expiry });

  } catch (e) {
    return json({ valid: false, error: 'server_error' }, 500);
  }
}

// ══════════════════════════════════════════════════════════════
// /register — העברת נתוני הרשמה ל-Make (ללא חשיפת ה-URL)
// ══════════════════════════════════════════════════════════════
async function handleRegister(request, env) {
  try {
    const body = await request.json();
    const { name, email, plan, registered_at, source } = body;

    // ולידציה בסיסית
    if (!email || !email.includes('@')) {
      return json({ ok: false, error: 'invalid_email' }, 400);
    }

    const makeUrl = env.MAKE_WEBHOOK_URL;
    if (!makeUrl) {
      // אם ה-URL לא מוגדר — לא חוסמים את ההרשמה
      return json({ ok: true, warning: 'make_not_configured' });
    }

    // שלח ל-Make
    const makeResp = await fetch(makeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event: 'register',
        name: name || '',
        email: email.toLowerCase().trim(),
        plan: plan || 'trial',
        registered_at: registered_at || new Date().toISOString(),
        source: source || 'direct'
      })
    });

    return json({ ok: makeResp.ok });

  } catch (e) {
    // לא חוסמים הרשמה בגלל שגיאת Make
    return json({ ok: false, error: 'make_error' });
  }
}

// ── helper ─────────────────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}
