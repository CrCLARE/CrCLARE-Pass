// ============================================================
// Nexus - Setup & Bootstrap Route
// SECURITY: Implements the double-gate initialization logic.
// Prevents unauthorized first-run registration.
// ============================================================

import { json, error } from '../utils/response.js';
import { generateUUID, hashPassword, constantTimeEqual } from '../utils/crypto.js';
import { signJwt, createSessionCookie } from '../services/jwt.js';

export async function handleSetupAPI(request, env) {
  if (request.method !== 'POST') {
    return error('ERR_METHOD', 'Method not allowed', 405);
  }

  try {
    const body = await request.json();
    const { bootstrap_password, email, password } = body;

    // GATE 1: Verify Bootstrap Password
    if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
      return error('ERR_MISSING', 'Missing configuration', 400);
    }

    // SECURITY: Constant-time comparison to prevent timing attacks
    const isPasswordValid = constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD);
    if (!isPasswordValid) {
      // SECURITY: Deliberately vague error message
      return error('ERR_INVALID_PWD', 'Invalid bootstrap password', 401);
    }

    // Check if the system is already initialized (Race condition prevention)
    const isInit = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'is_initialized'").first();
    if (isInit && isInit.value === 'true') {
      return error('ERR_ALREADY_INIT', 'System already initialized', 403);
    }

    // GATE 2: Create Super Admin
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

    const setInit = env.DB.prepare(
      `INSERT INTO system_settings (key, value) VALUES ('is_initialized', 'true')`
    );
    
    // Insert default site configs
    const setSiteName = env.DB.prepare(
      `INSERT INTO system_settings (key, value) VALUES ('site_name', 'Nexus')`
    );
    const setTermsVersion = env.DB.prepare(
      `INSERT INTO system_settings (key, value) VALUES ('terms_version', 'v1.0')`
    );

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

  } catch (e) {
    console.error('[Setup Error]', e);
    return error('ERR_INTERNAL', 'Internal Server Error during setup', 500);
  }
}
