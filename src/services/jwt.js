// ============================================================
// Nexus - JWT Service (WebCrypto)
// SECURITY: Uses HttpOnly Cookies for the web UI to prevent XSS,
// and returns short-lived JWTs for external API access.
// ============================================================

import { bufferToBase64Url, base64UrlToBuffer } from '../utils/encoder.js';

const ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };

async function getCryptoKey(secret) {
  return await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), ALGORITHM, false, ['sign', 'verify']);
}

export async function signJwt(payload, secret, ttlSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + ttlSeconds };

  const encodedHeader = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(header)).buffer);
  const encodedPayload = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(fullPayload)).buffer);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  
  const key = await getCryptoKey(secret);
  const signature = await crypto.subtle.sign(ALGORITHM, key, new TextEncoder().encode(dataToSign));
  
  return `${dataToSign}.${bufferToBase64Url(signature)}`;
}

export async function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const key = await getCryptoKey(secret);
  const signatureBuffer = base64UrlToBuffer(encodedSignature);

  const isValid = await crypto.subtle.verify(ALGORITHM, key, signatureBuffer, new TextEncoder().encode(dataToSign));
  if (!isValid) throw new Error('Invalid signature');

  const payload = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(encodedPayload)));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

  return payload;
}

export function createSessionCookie(token, ttlSeconds) {
  return `nexus_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${ttlSeconds}`;
}
