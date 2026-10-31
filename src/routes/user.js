// ============================================================
// Nexus - User API Routes
// SECURITY: Requires valid session. Enforces strict IDOR prevention
// by pulling user ID from the verified token, not the request body.
// ============================================================

import { json, error } from '../utils/response.js';
import { getAuthenticatedUser } from '../middleware/auth.js';

export async function handleUserAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 1. Enforce User Authentication
  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    return error('ERR_UNAUTHORIZED', 'Authentication required', 401);
  }

  // ==========================================
  // GET /api/user/me
  // Fetch current user's full profile
  // ==========================================
  if (path === '/api/user/me' && request.method === 'GET') {
    try {
      // Fetch basic info
      const profile = await env.DB.prepare(
        "SELECT id, email, role, app_enabled, created_at FROM users WHERE id = ?"
      ).bind(user.id).first();

      // Fetch bound OAuths
      const oauths = await env.DB.prepare(
        "SELECT provider FROM oauth_accounts WHERE user_id = ?"
      ).bind(user.id).all();
      
      const boundOAuths = oauths.results.map(o => o.provider);

      return json({
        nexusId: profile.id,
        email: profile.email,
        role: profile.role,
        appEnabled: profile.app_enabled === 1,
        createdAt: profile.created_at,
        boundOAuths: boundOAuths,
        // domains: [] // TODO: Fetch from domain verification table
      });
    } catch (e) {
      return error('ERR_DB', 'Failed to fetch user data', 500);
    }
  }

  // ==========================================
  // POST /api/user/update-profile
  // (Placeholder for updating display name)
  // ==========================================
  if (path === '/api/user/update-profile' && request.method === 'POST') {
    try {
      const { nickname } = await request.json();
      
      // SECURITY: Nickname length validation
      if (!nickname || nickname.length > 32) {
        return error('ERR_INVALID_INPUT', 'Invalid nickname', 400);
      }

      // SECURITY: Use user.id from the token, NEVER trust a user_id in the body (IDOR prevention)
      await env.DB.prepare(
        "UPDATE users SET updated_at = ? WHERE id = ?"
      ).bind(Date.now(), user.id).run();
      
      // Note: In a real schema, you'd update a 'nickname' column here.
      return json({ success: true, message: 'Profile updated' });
    } catch (e) {
      return error('ERR_DB', 'Failed to update profile', 500);
    }
  }

  // ==========================================
  // POST /api/user/domain/verify
  // SECURITY: Initiates TXT record verification
  // ==========================================
  if (path === '/api/user/domain/verify' && request.method === 'POST') {
    try {
      const { domain } = await request.json();
      
      if (!domain) return error('ERR_INVALID_INPUT', 'Domain required', 400);

      // TODO: Implement Cloudflare DNS over HTTPS (DoH) lookup
      // 1. Generate a unique token: `nexus-verify=${crypto.randomUUID()}`
      // 2. Query DoH API: https://cloudflare-dns.com/dns-query?name=${domain}&type=TXT
      // 3. Check if the token exists in the response.
      // 4. If valid, insert into a `verified_domains` table.
      
      return json({ success: true, message: 'Verification logic to be implemented' });
    } catch (e) {
      return error('ERR_DB', 'Failed to verify domain', 500);
    }
  }

  return error('ERR_NOT_FOUND', 'User route not found', 404);
}
