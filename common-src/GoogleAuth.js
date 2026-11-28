// Google sign-in for the admin area (Cloudflare Pages Functions).
// Flow: /admin/auth/login redirects to Google -> Google redirects back to
// /admin/auth/callback with a code -> the code is exchanged for an ID token,
// the token is checked with Google, and a signed session cookie is set.
// The cookie is what the admin middleware checks; clearing it logs out.
// Only Google accounts listed in ADMIN_EMAILS may sign in.
export const SESSION_COOKIE = 'mf_session';
export const STATE_COOKIE = 'mf_oauth_state';
export const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

function b64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(s + '='.repeat((4 - (s.length % 4)) % 4));
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) {
      return rest.join('=');
    }
  }
  return null;
}

export function getAllowedEmails(env) {
  return (env.ADMIN_EMAILS || 'brightmann@gmail.com')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

export function getRedirectUri(request) {
  return `${new URL(request.url).origin}/admin/auth/callback`;
}

export function getGoogleAuthUrl(env, request, state) {
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: getRedirectUri(request),
    response_type: 'code',
    scope: 'openid email',
    state,
    prompt: 'select_account',
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

export function randomState() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function createSessionCookieValue(env, email) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE;
  const payload = b64urlEncode(`${email}.${exp}`);
  const sig = await hmacHex(env.SESSION_SECRET, payload);
  return `${payload}.${sig}`;
}

// Returns the signed-in email, or null when there is no valid session.
export async function verifySessionCookie(env, value) {
  if (!value || !env.SESSION_SECRET) {
    return null;
  }
  const [payload, sig] = value.split('.');
  if (!payload || !sig) {
    return null;
  }
  const expected = await hmacHex(env.SESSION_SECRET, payload);
  if (!timingSafeEqual(sig, expected)) {
    return null;
  }
  let decoded;
  try {
    decoded = b64urlDecode(payload);
  } catch (e) {
    return null;
  }
  const [email, exp] = decoded.split('.');
  if (!email || !exp || Number(exp) < Date.now() / 1000) {
    return null;
  }
  return email;
}
