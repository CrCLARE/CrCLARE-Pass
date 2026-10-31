// ============================================================
// Nexus - Main Entry Point (Cloudflare Workers)
// SECURITY: Handles Bootstrap interception, API routing, 
// and static asset serving. Enforces zero-trust by default.
// ============================================================

import { json, error } from './utils/response.js';
import { handleSetupAPI } from './routes/setup.js';
import { getPublicConfig } from './routes/config.js';
import { handleAuthAPI } from './routes/auth.js';
import { handleOAuth } from './routes/oauth.js';
import { handleAdminAPI } from './routes/admin.js';
import { handleUserAPI } from './routes/user.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ============================================================
      // 1. Bootstrap Check (The First Gate)
      // SECURITY: If the system is not initialized, NO API routes 
      // (except setup) are accessible. All frontend routes redirect to setup.
      // ============================================================
      let isInitialized = false;
      
      try {
        // Fail-safe: If DB is down or empty, assume NOT initialized.
        const result = await env.DB.prepare(
          "SELECT value FROM system_settings WHERE key = 'is_initialized'"
        ).first();
        isInitialized = result && result.value === 'true';
      } catch (e) {
        isInitialized = false; 
      }

      // Handle uninitialized state
      if (!isInitialized) {
        if (path === '/api/setup') {
          return handleSetupAPI(request, env);
        }
        
        // Block all other API requests
        if (path.startsWith('/api/')) {
          return error('ERR_NOT_INIT', 'System not initialized', 403);
        }
        
        // Redirect all frontend page requests to the setup page
        // (Ignore static file requests like .css, .js)
        if (!path.includes('.') && path !== '/setup.html') {
          return Response.redirect(`${url.origin}/setup.html`, 302);
        }
      }

      // ============================================================
      // 2. Prevent accessing setup after initialization
      // SECURITY: Once initialized, the setup API is permanently locked.
      // ============================================================
      if (isInitialized && path === '/api/setup') {
        return error('ERR_ALREADY_INIT', 'System already initialized', 403);
      }

      // ============================================================
      // 3. API Routing (After Initialization)
      // ============================================================
      if (path.startsWith('/api/')) {
        
        // Public Configuration
        if (path === '/api/config/public' && request.method === 'GET') {
          return getPublicConfig(env);
        }
        
        // Authentication (Login, Register, Verify Email)
        if (path.startsWith('/api/auth')) {
          return handleAuthAPI(request, env);
        }

        // OAuth (GitHub, Consent, Callbacks)
        if (path.startsWith('/api/oauth')) {
          return handleOAuth(request, env);
        }

        // Admin Operations (Settings, User Management)
        if (path.startsWith('/api/admin')) {
          return handleAdminAPI(request, env);
        }

        // User Operations (Profile, Security, Export)
        if (path.startsWith('/api/user')) {
          return handleUserAPI(request, env);
        }
        
        // Fallback for undefined API routes
        return error('ERR_NOT_FOUND', 'API route not found', 404);
      }

      // ============================================================
      // 4. Serve Static Files (Frontend UI)
      // SECURITY: Cloudflare Workers Assets handles the secure serving 
      // of HTML, CSS, JS, and images from the /public directory.
      // ============================================================
      return env.ASSETS.fetch(request);

    } catch (e) {
      // ============================================================
      // 5. Global Error Handler
      // SECURITY: Never leak stack traces to the client.
      // ============================================================
      console.error('[Nexus Core Error]', e);
      return error('ERR_SYSTEM_ERROR', 'Internal Server Error', 500);
    }
  }
};
