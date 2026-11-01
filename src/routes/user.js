// ============================================================
// Nexus - User API Routes
// SECURITY: Requires valid session. Enforces strict IDOR prevention
// by pulling user ID from the verified token, not the request body.
// ============================================================

import { json, error } from '../utils/response.js';
import { getAuthenticatedUser } from '../middleware/auth.js';
import { hashPassword, verifyPassword } from '../utils/crypto.js';

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
  // ==========================================
  if (path === '/api/user/me' && request.method === 'GET') {
    try {
      const profile = await env.DB.prepare(
        "SELECT id, email, role, nickname, app_enabled, created_at FROM users WHERE id = ?"
      ).bind(user.id).first();

      const oauths = await env.DB.prepare(
        "SELECT provider FROM oauth_accounts WHERE user_id = ?"
      ).bind(user.id).all();
      
      const passkeys = await env.DB.prepare(
        "SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?"
      ).bind(user.id).first();

      const boundOAuths = oauths.results ? oauths.results.map(o => o.provider) : [];

      return json({
        nexusId: profile.id,
        email: profile.email,
        role: profile.role,
        nickname: profile.nickname || profile.email.split('@')[0], // Fallback to email prefix
        appEnabled: profile.app_enabled === 1,
        passkeysCount: passkeys ? passkeys.count : 0,
        createdAt: profile.created_at,
        boundOAuths: boundOAuths
      });
    } catch (e) {
      return error('ERR_DB', 'Failed to fetch user data', 500);
    }
  }

  // ==========================================
  // POST /api/user/update-profile
  // ==========================================
  if (path === '/api/user/update-profile' && request.method === 'POST') {
    try {
      const { nickname } = await request.json();
      
      if (!nickname || nickname.length > 32) {
        return error('ERR_INVALID_INPUT', 'Invalid nickname (Max 32 chars)', 400);
      }

      await env.DB.prepare(
        "UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?"
      ).bind(nickname, Date.now(), user.id).run();
      
      return json({ success: true, message: 'Profile updated' });
    } catch (e) {
      return error('ERR_DB', 'Failed to update profile', 500);
    }
  }

  // ==========================================
  // POST /api/user/change-password
  // ==========================================
  if (path === '/api/user/change-password' && request.method === 'POST') {
    try {
      const { oldPassword, newPassword } = await request.json();
      if (!oldPassword || !newPassword || newPassword.length < 8) {
        return error('ERR_INVALID_INPUT', 'Invalid password format', 400);
      }

      const dbUser = await env.DB.prepare("SELECT password_hash, password_salt FROM users WHERE id = ?").bind(user.id).first();
      
      // SECURITY: Verify old password before allowing change
      if (dbUser.password_hash) {
        const isValid = await verifyPassword(oldPassword, dbUser.password_hash, dbUser.password_salt);
        if (!isValid) return error('ERR_INVALID_CREDENTIALS', 'Incorrect old password', 401);
      }

      const { hash, salt } = await hashPassword(newPassword);
      await env.DB.prepare(
        "UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?"
      ).bind(hash, salt, Date.now(), user.id).run();

      return json({ success: true, message: 'Password changed successfully' });
    } catch (e) {
      return error('ERR_DB', 'Failed to change password', 500);
    }
  }

  // ==========================================
  // GET /api/user/export
  // SECURITY: Generates a JSON payload of all user data (GDPR)
  // ==========================================
  if (path === '/api/user/export' && request.method === 'GET') {
    try {
      // Check if admin allows export
      const allowExport = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'allow_uc_export'").first();
      if (allowExport && allowExport.value === 'false') {
        return error('ERR_FORBIDDEN', 'Data export is disabled by administrator', 403);
      }

      const profile = await env.DB.prepare("SELECT id, email, role, nickname, created_at FROM users WHERE id = ?").bind(user.id).first();
      const oauths = await env.DB.prepare("SELECT provider, created_at FROM oauth_accounts WHERE user_id = ?").bind(user.id).all();
      
      const exportData = {
        export_date: new Date().toISOString(),
        nexus_id: profile.id,
        email: profile.email,
        nickname: profile.nickname,
        role: profile.role,
        joined_at: profile.created_at,
        connected_accounts: oauths.results || []
      };

      const headers = {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="nexus-export-${profile.id}.json"`
      };

      return new Response(JSON.stringify(exportData, null, 2), { status: 200, headers });
    } catch (e) {
      return error('ERR_DB', 'Failed to export data', 500);
    }
  }

  // ==========================================
  // POST /api/user/delete-account
  // ==========================================
  if (path === '/api/user/delete-account' && request.method === 'POST') {
    try {
      // SECURITY: Soft-delete or hard-delete. Here we do a hard delete (cascade deletes bindings)
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id).run();
      
      // Clear session cookie
      const cookieHeader = 'nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
      return json({ success: true, message: 'Account deleted' }, 200, { 'Set-Cookie': cookieHeader });
    } catch (e) {
      return error('ERR_DB', 'Failed to delete account', 500);
    }
  }

  return error('ERR_NOT_FOUND', 'User route not found', 404);
}