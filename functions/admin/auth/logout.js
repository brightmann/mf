import {SESSION_COOKIE} from '../../../common-src/GoogleAuth';

export async function onRequestGet({request}) {
  const url = new URL(request.url);
  const headers = new Headers({Location: `${url.origin}/`});
  headers.append('Set-Cookie',
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/admin; Max-Age=0`);
  return new Response(null, {status: 302, headers});
}
