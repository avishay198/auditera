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
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

    // ── POST /notify — אירועי login ו-profile_update ──────────
    if (request.method === 'POST' && url.pathname === '/notify') {
      return handleNotify(request, env);
    }

    // ── POST /admin-auth — אימות סיסמת מנהל ─────────────────────
    if (request.method === 'POST' && url.pathname === '/admin-auth') {
      return handleAdminAuth(request, env);
    }

    // ── POST /generate-token — יצירת טוקן רישיון (מנהל בלבד) ────
    if (request.method === 'POST' && url.pathname === '/generate-token') {
      return handleGenerateToken(request, env);
    }

    // ── GET /lookup — בדיקת רישיון אוטומטית לפי אימייל (ללא HMAC) ────
    if (request.method === 'GET' && url.pathname === '/lookup') {
      return handleLookup(request, env);
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
      headers: {
        'Content-Type': 'application/json',
        ...(env.MAKE_APIKEY ? { 'x-make-apikey': env.MAKE_APIKEY } : {})
      },
      body: JSON.stringify({
        event: 'register',
        name: name || '',
        email: email.toLowerCase().trim(),
        plan: plan || 'trial',
        registered_at: registered_at || new Date().toISOString(),
        source: source || 'direct'
      })
    });

    const respText = await makeResp.text(); return json({ ok: makeResp.ok, status: makeResp.status, body: respText });

  } catch (e) {
    // לא חוסמים הרשמה בגלל שגיאת Make
    return json({ ok: false, error: 'make_error' });
  }
}


// ══════════════════════════════════════════════════════════════
// /notify — אירועי login ו-profile_update מ-login.html
// ══════════════════════════════════════════════════════════════
async function handleNotify(request, env) {
  try {
    const body = await request.json();
    const { event, email } = body;

    if (!event || !email) {
      return json({ ok: false, error: 'missing_params' }, 400);
    }

    const makeUrl = env.MAKE_WEBHOOK_URL;
    if (!makeUrl) {
      return json({ ok: true, warning: 'make_not_configured' });
    }

    // שלח ל-Make רק אירועים ידועים
    if (!['register', 'login', 'profile_update', 'contact', 'payment_request'].includes(event)) {
      return json({ ok: false, error: 'unknown_event' }, 400);
    }

    const makeResp = await fetch(makeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(env.MAKE_APIKEY ? { 'x-make-apikey': env.MAKE_APIKEY } : {})
      },
      body: JSON.stringify(body)
    });

    const respText = await makeResp.text(); return json({ ok: makeResp.ok, status: makeResp.status, body: respText });

  } catch (e) {
    return json({ ok: false, error: 'server_error' });
  }
}

// ── helper ─────────────────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

// ══════════════════════════════════════════════════════════════
// /admin-auth — אימות סיסמת מנהל (hash מאוחסן כ-Cloudflare secret)
// הגדר ב-Dashboard: ADMIN_PASS_HASH, ADMIN_SALT
// ══════════════════════════════════════════════════════════════
async function handleAdminAuth(request, env) {
  try {
    const { password } = await request.json();
    if (!password) return json({ ok: false, error: 'missing_password' }, 400);

    const salt   = env.ADMIN_SALT   || '';
    const stored = env.ADMIN_PASS_HASH || '';
    if (!stored) return json({ ok: false, error: 'not_configured' }, 500);

    // SHA-256(password + salt) — אותו אלגוריתם כמו _hashPassLegacy
    const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + salt));
    const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');

    if (hash !== stored) return json({ ok: false, error: 'invalid' });

    // הפק session token תקף ל-8 שעות
    const expires = Date.now() + 8 * 3600 * 1000;
    const payload = `admin|${expires}`;
    const secret  = env.LIC_SECRET || '';
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
    const token = btoa(payload + '|' + sigHex);

    return json({ ok: true, token, expires });
  } catch (e) {
    return json({ ok: false, error: 'server_error' }, 500);
  }
}

// ══════════════════════════════════════════════════════════════
// /generate-token — יצירת טוקן רישיון HMAC-SHA256
// דורש אימות מנהל (admin_token מ-/admin-auth)
// ══════════════════════════════════════════════════════════════
async function handleGenerateToken(request, env) {
  try {
    const { email, plan, quota, expiry, admin_token } = await request.json();

    // אמת שהמבקש הוא מנהל
    if (!admin_token) return json({ ok: false, error: 'unauthorized' }, 401);
    try {
      const decoded = atob(admin_token);
      const lastPipe = decoded.lastIndexOf('|');
      const payload  = decoded.slice(0, lastPipe);
      const sig      = decoded.slice(lastPipe + 1);
      if (!payload.startsWith('admin|')) return json({ ok: false, error: 'unauthorized' }, 401);
      const expires = parseInt(payload.split('|')[1]);
      if (Date.now() > expires) return json({ ok: false, error: 'session_expired' }, 401);
      // אמת חתימה
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.LIC_SECRET || ''),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const expected = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
      const expHex = Array.from(new Uint8Array(expected)).map(b=>b.toString(16).padStart(2,'0')).join('');
      if (expHex !== sig) return json({ ok: false, error: 'unauthorized' }, 401);
    } catch(e) {
      return json({ ok: false, error: 'unauthorized' }, 401);
    }

    // ולידציה
    if (!email || !email.includes('@')) return json({ ok: false, error: 'invalid_email' }, 400);
    if (!plan || !expiry) return json({ ok: false, error: 'missing_params' }, 400);

    const q = parseInt(quota) || 60;
    const payload = `${plan}|${q}|${expiry}|${email.toLowerCase().trim()}`;

    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.LIC_SECRET),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    const hmac = Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,'0')).join('');
    const token = btoa(`${payload}|${hmac}`);

    // שמור ב-KV — כולל הטוקן המלא לאימות אוטומטי
    if (env.LICENSES) {
      await env.LICENSES.put(
        'license:' + email.toLowerCase().trim(),
        JSON.stringify({ plan, quota: q, expiry, token }),
        { expirationTtl: 60 * 60 * 24 * 400 } // ~13 חודשים
      );
    }

    return json({ ok: true, token });
  } catch(e) {
    return json({ ok: false, error: 'server_error' }, 500);
  }
}

// ══════════════════════════════════════════════════════════════
// /lookup — אחזור רישיון לפי אימייל (GET, ללא HMAC)
// מחזיר plan/quota/expiry בלבד — לא את הטוקן המלא
// ══════════════════════════════════════════════════════════════
async function handleLookup(request, env) {
  try {
    const url = new URL(request.url);
    const email = (url.searchParams.get('email') || '').toLowerCase().trim();
    if (!email || !email.includes('@')) {
      return json({ ok: false, error: 'missing_email' }, 400);
    }
    if (!env.LICENSES) {
      return json({ ok: false, error: 'kv_not_configured' });
    }
    const raw = await env.LICENSES.get('license:' + email);
    if (!raw) return json({ ok: false, error: 'not_found' });
    const { plan, quota, expiry, token } = JSON.parse(raw);
    // בדוק תאריך פקיעה
    const [yr, mo] = expiry.split('-').map(Number);
    if (new Date() >= new Date(yr, mo, 1)) {
      return json({ ok: false, error: 'expired' });
    }
    // אמת את הטוקן (HMAC) לפני החזרה
    if (token) {
      let decoded;
      try { decoded = atob(token.trim()); } catch { return json({ ok: false, error: 'invalid_token' }); }
      const lastPipe = decoded.lastIndexOf('|');
      const payload = decoded.slice(0, lastPipe);
      const tokenHmac = decoded.slice(lastPipe + 1);
      const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(env.LIC_SECRET || ''),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
      const expectedHmac = Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,'0')).join('');
      if (expectedHmac !== tokenHmac) return json({ ok: false, error: 'invalid_signature' });
    }
    // מחזיר רק מטא-דאטה — הטוקן לא נחשף החוצה
    return json({ ok: true, plan, quota, expiry });
  } catch(e) {
    return json({ ok: false, error: 'server_error' }, 500);
  }
}
