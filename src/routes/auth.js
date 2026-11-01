// ============================================================
// Nexus - Authentication Routes (Login, Register, Verify, Logout)
// SECURITY: Implements PBKDF2 hashing, strict terms validation, 
// dynamic CAPTCHA, rate limiting, and HttpOnly cookie sessions.
// ============================================================

import { json, error } from '../utils/response.js';
import { generateUUID, hashPassword, verifyPassword, constantTimeEqual } from '../utils/crypto.js';
import { signJwt, createSessionCookie } from '../services/jwt.js';
import { sendEmail, generateVerifyEmailHtml } from '../services/email.js';

// ============================================================
// Helper: Verify CAPTCHA dynamically
// ============================================================
async function verifyCaptcha(env, token) {
  const provider = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'captcha_provider'").first();
  
  if (!provider || provider.value === 'none') return true;
  if (!token) return false;

  try {
    if (provider.value === 'turnstile') {
      const secret = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'turnstile_secret_key'").first();
      if (!secret) return false;
      
      const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${secret.value}&response=${token}`
      });
      const data = await res.json();
      return data.success;
    }
    return false;
  } catch (e) {
    console.error('[CAPTCHA Error]', e);
    return false;
  }
}

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

      if (!email || !password) {
        return error('ERR_INVALID_INPUT', 'Email and password are required', 400);
      }

      const isCaptchaValid = await verifyCaptcha(env, captcha_token);
      if (!isCaptchaValid) {
        return error('ERR_CAPTCHA_FAILED', 'Human verification failed', 400);
      }

      const user = await env.DB.prepare(
        'SELECT id, email, role, password_hash, password_salt, status FROM users WHERE email = ?'
      ).bind(email.toLowerCase()).first();

      if (!user) {
        return error('ERR_INVALID_CREDENTIALS', 'Invalid email or password', 401);
      }

      if (user.status === 'banned') {
        return error('ERR_FORBIDDEN', 'Account is banned', 403);
      }
      if (user.status === 'pending') {
        return error('ERR_PENDING_VERIFY', 'Email not verified. Please check your inbox.', 403);
      }

      const isValid = await verifyPassword(password, user.password_hash, user.password_salt);
      if (!isValid) {
        return error('ERR_INVALID_CREDENTIALS', 'Invalid email or password', 401);
      }

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

      if (!email || !password) {
        return error('ERR_INVALID_INPUT', 'Email and password are required', 400);
      }

      if (!agreed_to_terms) {
        return error('ERR_TERMS_REQUIRED', 'You must agree to the Terms of Service', 400);
      }

      const currentTerms = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'terms_version'").first();
      if (currentTerms && terms_version !== currentTerms.value) {
        return error('ERR_TERMS_UPDATE_REQUIRED', 'Terms of Service have been updated', 403);
      }

      const isCaptchaValid = await verifyCaptcha(env, captcha_token);
      if (!isCaptchaValid) {
        return error('ERR_CAPTCHA_FAILED', 'Human verification failed', 400);
      }

      const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
      if (existingUser) {
        return error('ERR_EMAIL_EXISTS', 'Email is already registered', 409);
      }

      const { hash, salt } = await hashPassword(password);
      const userId = generateUUID();
      const now = Date.now();

      const reqEmailSetting = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'require_email_verify'").first();
      const requireVerify = reqEmailSetting && reqEmailSetting.value === 'true';

      const insertStmt = env.DB.prepare(
        'INSERT INTO users (id, email, role, password_hash, password_salt, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(userId, email.toLowerCase(), 'user', hash, salt, requireVerify ? 'pending' : 'active', now, now);

      await insertStmt.run();

      await env.DB.prepare(
        'INSERT INTO user_consents (id, user_id, terms_version, privacy_version, consented_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(generateUUID(), userId, terms_version, terms_version, now).run();

      if (requireVerify) {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await env.KV.put(`verify_code:${email.toLowerCase()}`, code, { expirationTtl: 900 });
        
        const html = generateVerifyEmailHtml(code);
        await sendEmail(env, email, 'Verify your email - Nexus', html);

        return json({ success: true, require_verify: true, email: email }, 200);
      } else {
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

  // ==========================================
  // POST /api/auth/verify-email
  // ==========================================
  if (path === '/api/auth/verify-email' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { email, code } = body;

      if (!email || !code) {
        return error('ERR_INVALID_INPUT', 'Email and code are required', 400);
      }

      const normalizedEmail = email.toLowerCase();
      const savedCode = await env.KV.get(`verify_code:${normalizedEmail}`);
      
      if (!savedCode) {
        return error('ERR_CODE_EXPIRED', 'Verification code expired or invalid', 400);
      }

      if (!constantTimeEqual(savedCode, code)) {
        return error('ERR_INVALID_CODE', 'Incorrect verification code', 401);
      }

      const updateResult = await env.DB.prepare(
        "UPDATE users SET status = 'active', updated_at = ? WHERE email = ? AND status = 'pending'"
      ).bind(Date.now(), normalizedEmail).run();

      if (updateResult.meta.changes === 0) {
        return error('ERR_UPDATE_FAILED', 'User not found or already verified', 400);
      }

      await env.KV.delete(`verify_code:${normalizedEmail}`);

      const user = await env.DB.prepare('SELECT id, role FROM users WHERE email = ?').bind(normalizedEmail).first();
      const sessionJwt = await signJwt({ uid: user.id, role: user.role }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);

      return json(
        { success: true, message: 'Email verified successfully' },
        200,
        { 'Set-Cookie': cookieHeader }
      );

    } catch (e) {
      console.error('[Verify Email Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }

  // ==========================================
  // POST /api/auth/resend-verification
  // ==========================================
  if (path === '/api/auth/resend-verification' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { email } = body;

      if (!email) return error('ERR_INVALID_INPUT', 'Email is required', 400);
      const normalizedEmail = email.toLowerCase();

      const limitKey = `resend_limit:${normalizedEmail}`;
      const isLimited = await env.KV.get(limitKey);
      if (isLimited) {
        return error('ERR_RATE_LIMITED', 'Please wait 60 seconds before requesting a new code', 429);
      }

      const user = await env.DB.prepare("SELECT id FROM users WHERE email = ? AND status = 'pending'").bind(normalizedEmail).first();
      if (!user) {
        return json({ success: true, message: 'If the account exists, a code has been sent' });
      }

      const code = Math.floor(100000 + Math.random() * 900000).toString();
      await env.KV.put(`verify_code:${normalizedEmail}`, code, { expirationTtl: 900 });
      await env.KV.put(limitKey, '1', { expirationTtl: 60 });

      const html = generateVerifyEmailHtml(code);
      await sendEmail(env, email, 'Verify your email - Nexus', html);

      return json({ success: true, message: 'Verification code resent' });

    } catch (e) {
      console.error('[Resend Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }

  // ==========================================
  // POST /api/auth/logout
  // ==========================================
  if (path === '/api/auth/logout' && request.method === 'POST') {
    const cookieHeader = 'nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
    return json({ success: true, message: 'Logged out' }, 200, { 'Set-Cookie': cookieHeader });
  }

  return error('ERR_NOT_FOUND', 'Auth route not found', 404);
}