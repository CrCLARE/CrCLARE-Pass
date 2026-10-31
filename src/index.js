// ============================================================
// Nexus (CrCLARE Identity Hub) - Main Entry Point
// SECURITY: This file implements the Bootstrap double-gate
// mechanism. No routes are accessible until the system is
// properly initialized via the environment variable.
// ============================================================

import { json, constantTimeEqual } from './utils.js'; // Assuming utils.js exists

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // SECURITY: Always apply strict security headers (Prevent XSS, Clickjacking)
    const securityHeaders = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      // Add a strict CSP later when frontend is ready
    };

    try {
      // --------------------------------------------------------
      // 1. Bootstrap Check (The First Gate)
      // --------------------------------------------------------
      const isInitialized = await checkSystemStatus(env);

      if (!isInitialized) {
        // Allow access to setup page and setup API only
        if (path === '/setup' || path === '/api/setup') {
          return handleSetup(request, env);
        }
        
        // SECURITY: If not initialized, force redirect everything else to /setup
        // This prevents any unauthorized access before the admin is created.
        if (path.startsWith('/api/')) {
          return json({ error: 'System not initialized. Access denied.' }, 403, securityHeaders);
        }
        
        return Response.redirect(`${url.origin}/setup`, 302);
      }

      // --------------------------------------------------------
      // 2. Normal Routing (System is initialized)
      // --------------------------------------------------------
      // From here, the system is ready. Route requests to their
      // respective handlers (Auth, Profile, Admin, etc.)
      
      if (path === '/setup' || path === '/api/setup') {
        // SECURITY: Once initialized, the setup route is permanently locked.
        return new Response('System is already initialized.', { status: 403, headers: securityHeaders });
      }

      // Route examples (to be implemented)
      if (path.startsWith('/api/auth')) {
        // return handleAuth(request, env);
        return json({ message: 'Auth API ready' }, 200, securityHeaders);
      }

      // Fallback for frontend assets
      return new Response('Nexus is online. En Taro Adun!', { status: 200, headers: securityHeaders });

    } catch (error) {
      console.error('[Nexus Core Error]', error);
      // SECURITY: Never leak stack traces or internal errors to the client
      return json({ error: 'Internal Server Error' }, 500, securityHeaders);
    }
  }
};

// ============================================================
// Helper Functions
// ============================================================

/**
 * Checks if the system has been initialized.
 * SECURITY: Uses parameterized query to prevent SQL Injection.
 */
async function checkSystemStatus(env) {
  try {
    // SECURITY: Fail-safe. If DB is down or empty, assume NOT initialized.
    const stmt = env.DB.prepare(
      "SELECT value FROM system_settings WHERE key = 'is_initialized'"
    );
    const result = await stmt.first();
    
    // Explicitly check for string 'true'
    return result && result.value === 'true';
  } catch (e) {
    console.error('DB check failed, assuming uninitialized', e);
    return false; 
  }
}

/**
 * Handles the setup process (The Second Gate).
 * Validates the INIT_ADMIN_PASSWORD before allowing actual setup.
 */
async function handleSetup(request, env) {
  const url = new URL(request.url);
  const securityHeaders = { 'Content-Type': 'text/html' };

  if (request.method === 'GET') {
    // Serve the setup HTML page (To be implemented)
    return new Response('<h1>Nexus Setup - Enter Bootstrap Password</h1>', { headers: securityHeaders });
  }

  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { bootstrap_password } = body;

      if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
        return json({ error: 'Missing credentials' }, 400);
      }

      // SECURITY: Timing attack defense. Use constant-time comparison
      // for the bootstrap password to prevent guessing.
      const isValid = constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD);

      if (!isValid) {
        // SECURITY: Deliberately vague error message
        return json({ error: 'Invalid bootstrap password' }, 401);
      }

      // Password is correct. 
      // TODO: Handle the actual initialization form submission here.
      // (Create super_admin, set is_initialized = 'true', etc.)
      
      return json({ success: true, message: 'Password verified. Proceed to form.' });

    } catch (e) {
      return json({ error: 'Invalid request format' }, 400);
    }
  }

  return new Response('Method Not Allowed', { status: 405 });
}
