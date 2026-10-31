// ============================================================
// Nexus - Standard Response Helpers
// ============================================================

import { SECURITY_HEADERS } from '../config/constants.js';

/**
 * Returns a standardized JSON response with security headers.
 */
export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders }
  });
}

/**
 * Returns a standardized error response.
 * SECURITY: Never leak stack traces. Use error codes for i18n.
 */
export function error(code, message = 'An error occurred', status = 400, extraHeaders = {}) {
  return json({ error: { code, message } }, status, extraHeaders);
}
