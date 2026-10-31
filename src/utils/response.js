// ============================================================
// Nexus (CrCLARE Identity Hub) - Standard Response Helpers
// SECURITY: Every response MUST go through these helpers to 
// ensure strict security headers are always applied.
// ============================================================

// Define strict, default security headers for API responses
const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',       // Prevent MIME-sniffing vulnerabilities
  'X-Frame-Options': 'DENY',                 // Prevent Clickjacking
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  // SECURITY: API routes should not be cached to prevent token leakage via shared caches
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
};

/**
 * Returns a JSON success or general response.
 * @param {Object|Array} data - The payload to return.
 * @param {number} status - HTTP status code (default 200).
 * @param {Object} extraHeaders - Any additional headers required.
 */
export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...BASE_HEADERS,
      ...extraHeaders
    }
  });
}

/**
 * Returns a standardized error response.
 * SECURITY: Never leak stack traces or internal DB errors to the client.
 * Always use generic error messages.
 * @param {string} message - Safe error message for the client.
 * @param {number} status - HTTP status code (default 400).
 */
export function error(message, status = 400, extraHeaders = {}) {
  return json({ error: message }, status, extraHeaders);
}

/**
 * Redirects the client to a specific URL.
 * Used primarily in the Bootstrap logic.
 */
export function redirect(url, status = 302) {
  return new Response(null, {
    status,
    headers: {
      'Location': url,
      // SECURITY: Prevent browsers from caching the redirect (ensures fresh state check)
      'Cache-Control': 'no-store, no-cache, must-revalidate',
    }
  });
}
