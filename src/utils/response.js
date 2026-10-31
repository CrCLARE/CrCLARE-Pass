// ============================================================
// Nexus - Standard Response Helpers
// SECURITY: Every response MUST go through these helpers to 
// ensure strict security headers are always applied.
// ============================================================

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
};

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...BASE_HEADERS, ...extraHeaders }
  });
}

export function error(code, message, status = 400, extraHeaders = {}) {
  return json({ code, message }, status, extraHeaders);
}
