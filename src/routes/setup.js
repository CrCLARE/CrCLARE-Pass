// ============================================================
// Nexus - Setup & Bootstrap Route (Double Gate)
// SECURITY: No system access is granted until initialized.
// ============================================================

import { json, error } from '../utils/response.js';
import { constantTimeEqual } from '../utils/constantTime.js';
import { signJwt, verifyJwt, createSessionCookie } from '../services/jwt.js';

// Mock crypto functions (replace with actual PBKDF2/WebCrypto in production)
async function hashPassword(pwd) { return { hash: 'mock_hash', salt: 'mock_salt' }; }
function generateUUID() { return crypto.randomUUID(); }

export async function handleSetupAPI(request, env) {
  const url = new URL(request.url);
  const step = url.searchParams.get('step');

  if (request.method !== 'POST') return error('ERR_METHOD', 'Method not allowed', 405);

  try {
    const body = await request.json();

    // GATE 1: Verify Bootstrap Password
    if (step === 'verify') {
      const { bootstrap_password } = body;
      if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
        return error('ERR_MISSING', 'Missing configuration', 400);
      }

      // SECURITY: Constant-time comparison
      if (!constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD)) {
        return error('ERR_INVALID_PWD', 'Invalid bootstrap password', 401);
      }

      // Issue temporary 10-min setup token
      const setupToken = await signJwt({ purpose: 'setup' }, env.JWT_SECRET, 600);
      return json({ success: true, setup_token: setupToken });
    }

    // GATE 2: Initialize System
    if (step === 'init') {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return error('ERR_UNAUTHORIZED', 'Missing setup token', 401);
      }
      
      const token = authHeader.split(' ')[1];
      let payload;
      try {
        payload = await verifyJwt(token, env.JWT_SECRET);
      } catch (e) {
        return error('ERR_EXPIRED', 'Setup token expired or invalid', 401);
      }

      if (payload.purpose !== 'setup') return error('ERR_FORBIDDEN', 'Invalid token purpose', 403);

      const { email, password } = body;
      if (!email || !password || password.length < 8) {
        return error('ERR_INVALID_INPUT', 'Invalid email or password too short', 400);
      }

      const userId = generateUUID();
      const { hash, salt } = await hashPassword(password);
      const now = Date.now();

      // SECURITY: D1 Prepared Statements prevent SQL Injection
      const createAdmin = env.DB.prepare(
        `INSERT INTO users (id, email, role, password_hash, password_salt, created_at, updated_at) 
         VALUES (?, ?, 'super_admin', ?, ?, ?, ?)`
      ).bind(userId, email.toLowerCase(), hash, salt, now, now);

      const setInit = env.DB.prepare(
        `INSERT INTO system_settings (key, value) VALUES ('is_initialized', 'true')`
      );

      await env.DB.batch([createAdmin, setInit]);

      // Auto-login admin via HttpOnly Cookie
      const sessionJwt = await signJwt({ uid: userId, role: 'super_admin' }, env.JWT_SECRET, 86400);
      return json({ success: true }, 200, { 'Set-Cookie': createSessionCookie(sessionJwt, 86400) });
    }

    return error('ERR_INVALID_STEP', 'Invalid setup step', 400);
  } catch (e) {
    return error('ERR_INTERNAL', 'Internal Server Error', 500);
  }
}
