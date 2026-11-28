import {
  getCookie, getAllowedEmails, getRedirectUri, createSessionCookieValue,
  SESSION_COOKIE, SESSION_MAX_AGE, STATE_COOKIE,
} from '../../../common-src/GoogleAuth';

export async function onRequestGet({request, env}) {
  const fail = (msg, status = 400) => new Response(msg, {status});

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET) {
    return fail('Google login is not configured yet on the server.', 500);
  }

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const stateCookie = getCookie(request, STATE_COOKIE);
  if (!code || !state || !stateCookie || state !== stateCookie) {
    return fail('Invalid login attempt. Please try signing in again.');
  }
  if (url.searchParams.get('error')) {
    return fail(`Google sign-in was not completed (${url.searchParams.get('error')}).`);
  }

  // Exchange the code for tokens.
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: getRedirectUri(request),
      grant_type: 'authorization_code',
    }),
  });
  if (!tokenRes.ok) {
    return fail('Google sign-in failed while exchanging the login code. Please try again.');
  }
  const tokens = await tokenRes.json();
  if (!tokens.id_token) {
    return fail('Google sign-in failed (no identity token). Please try again.');
  }

  // Verify the ID token with Google.
  const infoRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${tokens.id_token}`);
  if (!infoRes.ok) {
    return fail('Google sign-in failed while checking the login. Please try again.');
  }
  const info = await infoRes.json();
  if (info.aud !== env.GOOGLE_CLIENT_ID) {
    return fail('Google sign-in failed (token was not issued for this blog).');
  }
  if (info.email_verified !== 'true') {
    return fail('Google sign-in failed (email address is not verified).');
  }
  const email = (info.email || '').toLowerCase();
  if (!getAllowedEmails(env).includes(email)) {
    return fail(`Signed in as ${email}, but that Google account is not allowed to manage this blog.`, 403);
  }

  const session = await createSessionCookieValue(env, email);
  const headers = new Headers({Location: `${url.origin}/admin/`});
  headers.append('Set-Cookie',
    `${SESSION_COOKIE}=${session}; HttpOnly; Secure; SameSite=Lax; Path=/admin; Max-Age=${SESSION_MAX_AGE}`);
  headers.append('Set-Cookie',
    `${STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/admin/auth; Max-Age=0`);
  return new Response(null, {status: 302, headers});
}
