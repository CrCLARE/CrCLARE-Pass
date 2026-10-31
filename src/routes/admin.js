// ============================================================
// Nexus - Admin API Routes
// SECURITY: Strictly restricted to admin roles. Uses parameterized 
// queries for settings update. Enforces a whitelist of editable keys.
// ============================================================

import { json, error } from '../utils/response.js';
import { requireAdmin } from '../middleware/auth.js';

// SECURITY: Only allow specific keys to be updated by the admin.
// This prevents attackers from overwriting 'is_initialized' or other critical flags.
const ALLOWED_SETTINGS = [
  'site_name', 'site_logo', 'powered_by_text',
  'require_email_verify', 'allow_uc_export',
  'pwd_min_length', 'pwd_require_strong',
  'captcha_provider', 'turnstile_site_key',
  'enabled_oauths', 'github_client_id', 'github_client_secret',
  'enable_cookie_banner'
];

export async function handleAdminAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 1. Enforce Admin Authorization for all routes in this handler
  const auth = await requireAdmin(request, env);
  if (!auth.authorized) return auth.response;

  // ==========================================
  // GET /api/admin/settings
  // ==========================================
  if (path === '/api/admin/settings' && request.method === 'GET') {
    try {
      const results = await env.DB.prepare("SELECT key, value FROM system_settings").all();
      
      const settings = {};
      if (results.results) {
        results.results.forEach(row => settings[row.key] = row.value);
      }
      
      // SECURITY: Do not send sensitive secrets in plain text to the frontend.
      // Just indicate if they exist.
      if (settings.github_client_secret) {
        settings.github_client_secret = '••••••••••••••••';
      }

      return json(settings);
    } catch (e) {
      return error('ERR_DB', 'Failed to fetch settings', 500);
    }
  }

  // ==========================================
  // POST /api/admin/settings
  // ==========================================
  if (path === '/api/admin/settings' && request.method === 'POST') {
    try {
      const body = await request.json();
      const statements = [];
      const now = Date.now();

      for (const [key, value] of Object.entries(body)) {
        // SECURITY: Whitelist check
        if (!ALLOWED_SETTINGS.includes(key)) continue;
        
        // SECURITY: Skip masked secrets if they haven't been changed
        if (key === 'github_client_secret' && value === '••••••••••••••••') continue;

        // SECURITY: Parameterized UPSERT
        statements.push(
          env.DB.prepare(`
            INSERT INTO system_settings (key, value, updated_at) 
            VALUES (?, ?, ?) 
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
          `).bind(key, String(value), now)
        );
      }

      if (statements.length > 0) {
        await env.DB.batch(statements);
      }

      return json({ success: true, message: 'Settings updated' });
    } catch (e) {
      console.error('[Admin API Error]', e);
      return error('ERR_DB', 'Failed to update settings', 500);
    }
  }

  // TODO: Add /api/admin/users for user management
  // TODO: Add /api/admin/logs for audit logs

  return error('ERR_NOT_FOUND', 'Admin route not found', 404);
}
