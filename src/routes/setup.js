// ============================================================
// Nexus - Setup & Bootstrap Route
// SECURITY: Implements the double-gate initialization logic.
// Prevents unauthorized first-run registration.
// ============================================================

import { json, error } from '../utils/response.js';
import { generateUUID, hashPassword, constantTimeEqual } from '../utils/crypto.js';
import { signJwt, verifyJwt, createSessionCookie } from '../services/jwt.js';

export async function handleSetupAPI(request, env) {
  if (request.method !== 'POST') {
    return error('ERR_METHOD', 'Method not allowed', 405);
  }

  try {
    const url = new URL(request.url);
    const step = url.searchParams.get('step');
    const body = await request.json();

    // ==========================================
    // GATE 1: Verify Bootstrap Password
    // ==========================================
    if (step === 'verify') {
      const { bootstrap_password } = body;

      if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
        return error('ERR_MISSING', 'Missing configuration', 400);
      }

      // SECURITY: Constant-time comparison to prevent timing attacks
      const isPasswordValid = constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD);
      if (!isPasswordValid) {
        return error('ERR_INVALID_PWD', 'Invalid bootstrap password', 401);
      }

      // Check if the system is already initialized
      const isInit = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'is_initialized'").first();
      if (isInit && isInit.value === 'true') {
        return error('ERR_ALREADY_INIT', 'System already initialized', 403);
      }

      // Issue temporary 10-min setup token
      const setupToken = await signJwt({ purpose: 'setup' }, env.JWT_SECRET, 600);
      return json({ success: true, setup_token: setupToken });
    }

    // ==========================================
    // GATE 2: Create Super Admin
    // ==========================================
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

      if (payload.purpose !== 'setup') {
        return error('ERR_FORBIDDEN', 'Invalid token purpose', 403);
      }

      const { email, password } = body;
      if (!email || !password || password.length < 8) {
        return error('ERR_INVALID_INPUT', 'Invalid email or password too short', 400);
      }

      const userId = generateUUID();
      const { hash, salt } = await hashPassword(password);
      const now = Date.now();

      // SECURITY: Parameterized queries
      const createAdmin = env.DB.prepare(
        `INSERT INTO users (id, email, role, password_hash, password_salt, status, created_at, updated_at) 
         VALUES (?, ?, 'super_admin', ?, ?, 'active', ?, ?)`
      ).bind(userId, email.toLowerCase(), hash, salt, now, now);

      // FIXED: Added updated_at field to match the schema constraint
      const setInit = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('is_initialized', 'true', ?)`
      ).bind(now);
      
      const setSiteName = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('site_name', 'Nexus', ?)`
      ).bind(now);
      
      const setTermsVersion = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('terms_version', 'v1.0', ?)`
      ).bind(now);

      // Execute batch transaction
      await env.DB.batch([createAdmin, setInit, setSiteName, setTermsVersion]);

      // Auto-login Super Admin
      const sessionJwt = await signJwt({ uid: userId, role: 'super_admin' }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);

      return json(
        { success: true, message: 'System initialized' },
        200,
        { 'Set-Cookie': cookieHeader }
      );
    }

    return error('ERR_INVALID_STEP', 'Invalid setup step', 400);

  } catch (e) {
    console.error('[Setup Error]', e);
    return error('ERR_INTERNAL', 'Internal Server Error during setup', 500);
  }
}