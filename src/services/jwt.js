// ============================================================
// Nexus (CrCLARE Identity Hub) - JWT Service
// Handles signing, verification, and secure cookie generation.
// ============================================================

import { bufferToBase64Url, base64UrlToBuffer } from '../utils/encoder.js';

// SECURITY: Use WebCrypto for HMAC-SHA256 signing (native Cloudflare support)
const ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };

/**
 * Helper to import the JWT secret into a CryptoKey.
 */
async function getCryptoKey(secret) {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    ALGORITHM,
    false,
    ['sign', 'verify']
  );
}

/**
 * Signs a payload into a JWT (HS256).
 */
export async function signJwt(payload, secret, ttlSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSeconds;
  
  // Add standard claims
  const fullPayload = { ...payload, iat: now, exp };

  // SECURITY: Use Base64URL encoding to comply with JWT RFC 7515
  const encodedHeader = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(header)).buffer);
  const encodedPayload = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(fullPayload)).buffer);
  
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  const key = await getCryptoKey(secret);
  
  const signature = await crypto.subtle.sign(
    ALGORITHM,
    key,
    new TextEncoder().encode(dataToSign)
  );
  
  const encodedSignature = bufferToBase64Url(signature);
  return `${dataToSign}.${encodedSignature}`;
}

/**
 * Verifies a JWT and returns the decoded payload.
 * SECURITY: Throws error if signature is invalid or token is expired.
 */
export async function verifyJwt(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const key = await getCryptoKey(secret);
  const signatureBuffer = base64UrlToBuffer(encodedSignature);

  // SECURITY: Constant-time HMAC verification is handled natively by WebCrypto
  const isValid = await crypto.subtle.verify(
    ALGORITHM,
    key,
    signatureBuffer,
    new TextEncoder().encode(dataToSign)
  );

  if (!isValid) throw new Error('Invalid signature');

  // Decode payload
  const payload = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(encodedPayload)));

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('Token expired');
  }

  return payload;
}

/**
 * Generates a secure Set-Cookie header string for HttpOnly sessions.
 * SECURITY: HttpOnly prevents XSS access. SameSite=Lax prevents CSRF.
 */
export function createSessionCookie(token, ttlSeconds) {
  return `nexus_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${ttlSeconds}`;
}

/**
 * Generates a cookie header to clear the session.
 */
export function clearSessionCookie() {
  return `nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
