// src/utils/hash.js

const encoder = new TextEncoder();

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const pwBuf = encoder.encode(password);
  const salted = new Uint8Array([...salt, ...pwBuf]);
  const hashBuf = await crypto.subtle.digest('SHA-256', salted);
  const full = new Uint8Array([...salt, ...new Uint8Array(hashBuf)]);
  return btoa(String.fromCharCode(...full));
}

export async function verifyPassword(password, storedHash) {
  const bin = atob(storedHash);
  const full = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const salt = full.slice(0, 16);
  const orig = full.slice(16);
  const pwBuf = encoder.encode(password);
  const testBuf = await crypto.subtle.digest(
    'SHA-256',
    new Uint8Array([...salt, ...pwBuf])
  );
  const test = new Uint8Array(testBuf);
  return orig.every((b, i) => b === test[i]);
}
