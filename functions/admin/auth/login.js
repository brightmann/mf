import {getGoogleAuthUrl, randomState, STATE_COOKIE} from '../../../common-src/GoogleAuth';

export async function onRequestGet({request, env}) {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response('Google login is not configured yet (missing GOOGLE_CLIENT_ID).', {status: 500});
  }
  const state = randomState();
  const headers = new Headers({Location: getGoogleAuthUrl(env, request, state)});
  headers.append('Set-Cookie',
    `${STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Path=/admin/auth; Max-Age=600`);
  return new Response(null, {status: 302, headers});
}
