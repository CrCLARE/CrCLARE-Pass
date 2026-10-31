// ============================================================
// Nexus (CrCLARE Identity Hub) - Constant Time Utilities
// SECURITY: Prevents Timing Attacks. Never use standard ===
// for comparing secrets, passwords, or cryptographic tokens.
// ============================================================

/**
 * Compares two strings in constant time (bitwise XOR accumulation).
 * SECURITY: The execution time depends only on the length of the strings, 
 * not the contents, preventing attackers from guessing secrets byte-by-byte.
 * 
 * @param {string} a - The first string (e.g., user input).
 * @param {string} b - The second string (e.g., stored hash).
 * @returns {boolean} True if strings are identical, false otherwise.
 */
export function constantTimeEqual(a, b) {
  // SECURITY: Type check. Do not allow non-string values to bypass.
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  // SECURITY: Length leak is acceptable for most use cases, 
  // but we still must iterate over the full length to prevent index guessing.
  const len = Math.max(a.length, b.length);
  let diff = 0;

  // Iterate over the maximum length. If lengths differ, the diff will become non-zero.
  for (let i = 0; i < len; i++) {
    // Use charCodeAt. If out of bounds, it returns NaN, but we bitwise OR it with 0.
    // SECURITY: Bitwise XOR (^) and OR (|) ensure the compiler/interpreter 
    // does not short-circuit or optimize the loop early.
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return diff === 0;
}

/**
 * Compares two ArrayBuffers (or Uint8Arrays) in constant time.
 * Useful for WebAuthn signature verification or raw byte comparisons.
 */
export function constantTimeEqualUint8Array(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
