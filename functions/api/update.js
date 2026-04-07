// POST /api/update - update progress data (requires Authorization: Bearer <key>)

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function validateProgress(data) {
  if (!data || typeof data !== 'object') return false;
  if (typeof data.percent !== 'number' || data.percent < 0 || data.percent > 100) return false;
  if (typeof data.matched !== 'number' || data.matched < 0) return false;
  if (typeof data.total !== 'number' || data.total < 0) return false;
  if (data.matched > data.total) return false;
  return JSON.stringify(data).length <= 500_000;
}

// Only the pusher backend should call /api/update, so CORS should be strict
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
};

// Simple rate limit: max 60 requests per minute (enough for the pusher's 6/min)
async function checkRateLimit(env, ip) {
  const key = `ratelimit:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / 60) * 60;
  const bucketKey = `${key}:${windowStart}`;

  try {
    const current = parseInt((await env.KV.get(bucketKey)) || '0', 10);
    if (current >= 60) return false;
    await env.KV.put(bucketKey, String(current + 1), { expirationTtl: 120 });
    return true;
  } catch {
    // Fail open if KV is down — don't block legit traffic
    return true;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (request.method !== 'POST') {
    return new Response('Method not allowed', {
      status: 405,
      headers: { ...CORS, 'Allow': 'POST' },
    });
  }

  // Rate limit (by IP)
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For') ||
             'unknown';
  const allowed = await checkRateLimit(env, ip);
  if (!allowed) {
    return new Response(JSON.stringify({ error: 'rate limit exceeded' }), {
      status: 429,
      headers: { ...SECURITY_HEADERS, ...CORS },
    });
  }

  // Auth check before parsing body (prevents JSON bomb attacks)
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ') || !safeEqual(auth.slice(7).trim(), env.WRITE_KEY || '')) {
    // Generic error — don't leak which part failed
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
      headers: { ...SECURITY_HEADERS, ...CORS },
    });
  }

  let data;
  try {
    data = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'invalid json' }), {
      status: 400,
      headers: { ...SECURITY_HEADERS, ...CORS },
    });
  }

  if (!validateProgress(data)) {
    return new Response(JSON.stringify({ error: 'invalid data' }), {
      status: 400,
      headers: { ...SECURITY_HEADERS, ...CORS },
    });
  }

  // Server overwrites the 'updated' field — client can't spoof it
  data.updated = new Date().toISOString();

  try {
    await env.KV.put('progress', JSON.stringify(data));
  } catch {
    return new Response(JSON.stringify({ error: 'storage error' }), {
      status: 500,
      headers: { ...SECURITY_HEADERS, ...CORS },
    });
  }

  return new Response(JSON.stringify({ ok: true, percent: data.percent, matched: data.matched }), {
    status: 200,
    headers: { ...SECURITY_HEADERS, ...CORS },
  });
}
