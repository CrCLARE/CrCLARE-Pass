// ============================================================
// Nexus (CrCLARE Identity Hub) - Encoding Utilities
// Handles ArrayBuffer, Base64URL, and Hex conversions.
// Crucial for WebAuthn (Passkeys) and database storage.
// ============================================================

/**
 * Converts an ArrayBuffer to a Base64URL encoded string.
 * SECURITY: Standard Base64 uses '+', '/', and '=', which are 
 * not URL-safe. WebAuthn strictly requires Base64URL.
 */
export function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Convert to Base64, then replace URL-unsafe characters
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Converts a Base64URL encoded string back to an ArrayBuffer.
 * Used when sending stored public keys back to the client or verifying signatures.
 */
export function base64UrlToBuffer(base64url) {
  // Add back the '=' padding that was removed
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Converts an ArrayBuffer to a Hex string.
 * Used for storing salts or hashes in D1.
 */
export function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a Hex string to an ArrayBuffer.
 */
export function hexToBuffer(hexString) {
  const bytes = new Uint8Array(Math.ceil(hexString.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes.buffer;
}
