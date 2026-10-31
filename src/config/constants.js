// ============================================================
// Nexus - Global Constants & Configuration
// ============================================================

// SECURITY: Standardized Error Codes (Mapped to frontend i18n)
export const ERRORS = {
  INVALID_INPUT: 'ERR_INVALID_INPUT',
  UNAUTHORIZED: 'ERR_UNAUTHORIZED',
  FORBIDDEN: 'ERR_FORBIDDEN',
  NOT_FOUND: 'ERR_NOT_FOUND',
  SYSTEM_ERROR: 'ERR_SYSTEM_ERROR',
  NOT_INITIALIZED: 'ERR_NOT_INITIALIZED',
  ALREADY_INITIALIZED: 'ERR_ALREADY_INITIALIZED',
  INVALID_CREDENTIALS: 'ERR_INVALID_CREDENTIALS',
  RATE_LIMITED: 'ERR_RATE_LIMITED',
  TERMS_UPDATE_REQUIRED: 'ERR_TERMS_UPDATE_REQUIRED',
};

// Default System Settings (Inserted into D1 during Bootstrap)
export const DEFAULT_SETTINGS = {
  is_initialized: 'false',
  site_name: 'Nexus',
  site_logo: '', // Defaults to SVG
  terms_version: 'v1.0',
  privacy_version: 'v1.0',
  require_terms_agreement: 'true',
  allow_uc_export: 'true',
  allow_banned_export: 'false',
  enable_cookie_banner: 'true',
  // Default Branding
  powered_by_text: 'Powered by Nexus',
  powered_by_url: 'https://github.com/CrCLARE/Nexus',
};

// Security Headers for API Responses
export const SECURITY_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
};
