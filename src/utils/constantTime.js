// ============================================================
// Nexus - Constant Time Utilities
// SECURITY: Prevents Timing Attacks. Never use standard ===
// for comparing secrets, passwords, or cryptographic tokens.
// ============================================================

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

export function constantTimeEqualUint8Array(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
