// src/utils/jwt.js

const encoder = new TextEncoder();

function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return atob(b64);
}

export async function signJWT(payload, secret) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));

  if (payload.exp && payload.exp > 1e12) {
    payload.exp = Math.floor(payload.exp / 1000);
  }

  const body = base64url(JSON.stringify(payload));
  const data = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const sig = base64url(String.fromCharCode(...new Uint8Array(sigBuf)));

  return `${data}.${sig}`;
}

export async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, body, sig] = parts;
  const data = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sigBuf = Uint8Array.from(base64urlDecode(sig), (c) => c.charCodeAt(0));
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    sigBuf,
    encoder.encode(data)
  );

  if (!valid) return null;

  const payload = JSON.parse(base64urlDecode(body));
  const nowSec = Math.floor(Date.now() / 1000);

  if (payload.exp && nowSec > payload.exp) return null;

  return payload;
}
