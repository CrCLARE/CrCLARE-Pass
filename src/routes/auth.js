// ============================================================
// Nexus - Authentication Routes (Login & Register)
// SECURITY: Implements PBKDF2 hashing, strict terms validation, 
// and HttpOnly cookie session issuance.
// ============================================================

import { json, error } from '../utils/response.js';
import { generateUUID, hashPassword, verifyPassword } from '../utils/crypto.js';
import { signJwt, createSessionCookie } from '../services/jwt.js';

export async function handleAuthAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // ==========================================
  // POST /api/auth/login
  // ==========================================
  if (path === '/api/auth/login' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { email, password, captcha_token } = body;

      // SECURITY: Basic validation
      if (!email || !password) {
        return error('ERR_INVALID_INPUT', 'Email and password are required', 400);
      }

      // TODO: Verify CAPTCHA token if enabled (Implement verifyCaptcha helper)

      // SECURITY: Parameterized query to prevent SQL Injection
      const user = await env.DB.prepare(
        'SELECT id, email, role, password_hash, password_salt, status FROM users WHERE email = ?'
      ).bind(email.toLowerCase()).first();

      if (!user) {
        // SECURITY: Generic error to prevent user enumeration
        return error('ERR_INVALID_CREDENTIALS', 'Invalid email or password', 401);
      }

      if (user.status === 'banned') {
        return error('ERR_FORBIDDEN', 'Account is banned', 403);
      }

      // SECURITY: Constant-time password verification
      const isValid = await verifyPassword(password, user.password_hash, user.password_salt);
      
      if (!isValid) {
        return error('ERR_INVALID_CREDENTIALS', 'Invalid email or password', 401);
      }

      // Issue HttpOnly Session Cookie
      const sessionJwt = await signJwt({ uid: user.id, role: user.role }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);

      return json(
        { success: true, user: { id: user.id, email: user.email, role: user.role } },
        200,
        { 'Set-Cookie': cookieHeader }
      );

    } catch (e) {
      console.error('[Login Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }

  // ==========================================
  // POST /api/auth/register
  // ==========================================
  if (path === '/api/auth/register' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { email, password, agreed_to_terms, terms_version, captcha_token } = body;

      // SECURITY: Validate required inputs
      if (!email || !password) {
        return error('ERR_INVALID_INPUT', 'Email and password are required', 400);
      }

      // SECURITY: Enforce GDPR/Terms Agreement (Backend check, cannot be bypassed)
      if (!agreed_to_terms) {
        return error('ERR_TERMS_REQUIRED', 'You must agree to the Terms of Service', 400);
      }

      // SECURITY: Validate Terms Version against the latest in DB
      const currentTerms = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'terms_version'").first();
      if (currentTerms && terms_version !== currentTerms.value) {
        return error('ERR_TERMS_UPDATE_REQUIRED', 'Terms of Service have been updated', 403);
      }

      // TODO: Verify CAPTCHA token if enabled

      // Check if user already exists
      const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (existingUser) {
        return error('ERR_EMAIL_EXISTS', 'Email is already registered', 409);
      }

      // Hash password and insert user
      const { hash, salt } = await hashPassword(password);
      const userId = generateUUID();
      const now = Date.now();

      // Check if email verification is required by admin
      const reqEmailSetting = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'require_email_verify'").first();
      const requireVerify = reqEmailSetting && reqEmailSetting.value === 'true';

      const insertStmt = env.DB.prepare(
        'INSERT INTO users (id, email, role, password_hash, password_salt, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(userId, email.toLowerCase(), 'user', hash, salt, requireVerify ? 'pending' : 'active', now, now);

      await insertStmt.run();

      // Record consent
      await env.DB.prepare(
        'INSERT INTO user_consents (id, user_id, terms_version, privacy_version, consented_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(generateUUID(), userId, terms_version, terms_version, now).run();

      // Handle Verification vs Direct Login
      if (requireVerify) {
        // TODO: Send verification email
        return json({ success: true, require_verify: true, email: email }, 200);
      } else {
        // Direct login
        const sessionJwt = await signJwt({ uid: userId, role: 'user' }, env.JWT_SECRET, 86400 * 7);
        const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);
        
        return json(
          { success: true, require_verify: false, user: { id: userId, email: email, role: 'user' } },
          200,
          { 'Set-Cookie': cookieHeader }
        );
      }

    } catch (e) {
      console.error('[Register Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }

  return error('ERR_NOT_FOUND', 'Auth route not found', 404);
}
