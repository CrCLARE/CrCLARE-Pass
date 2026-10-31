// ============================================================
// Nexus - Cryptography & Security Utilities
// SECURITY: Uses standard WebCrypto APIs. Implements constant-time 
// comparison and secure password hashing (PBKDF2).
// ============================================================

/**
 * Generates a random UUID v4.
 */
export function generateUUID() {
  return crypto.randomUUID();
}

/**
 * Constant-time string comparison to prevent Timing Attacks.
 * SECURITY: Do not use === for comparing secrets, tokens, or hashes.
 * Execution time depends only on string length, not the contents.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  
  const len = Math.max(a.length, b.length);
  let diff = 0;
  
  for (let i = 0; i < len; i++) {
    // SECURITY: Bitwise XOR and OR ensure no early exit.
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  
  return diff === 0;
}

/**
 * Constant-time ArrayBuffer comparison.
 * Used for WebAuthn signature verification.
 */
export function constantTimeEqualBuffer(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Hashes a password using PBKDF2-SHA256.
 * Returns { hash, salt } as hex strings.
 */
export async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw', 
    enc.encode(password), 
    { name: 'PBKDF2' }, 
    false, 
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );

  return {
    hash: Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join(''),
    salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  };
}

/**
 * Verifies a password against a stored hash and salt.
 * SECURITY: Uses constant-time comparison.
 */
export async function verifyPassword(password, storedHash, storedSaltHex) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(storedSaltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw', 
    enc.encode(password), 
    { name: 'PBKDF2' }, 
    false, 
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );

  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  
  // SECURITY: Constant-time comparison
  return constantTimeEqual(hash, storedHash);
}
