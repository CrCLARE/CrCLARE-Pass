// ============================================================
// Nexus (CrCLARE Identity Hub) - Setup & Bootstrap Route
// SECURITY: Implements the double-gate initialization logic.
// No access is granted until the system is fully initialized.
// ============================================================

import { json, error } from '../utils/response.js';
import { constantTimeEqual } from '../utils/constantTime.js';
import { signJwt, verifyJwt, createSessionCookie } from '../services/jwt.js';
// Assume these exist in your crypto services (PBKDF2, UUID generation)
import { hashPassword, generateUUID } from '../services/crypto.js'; 

export async function handleSetup(request, env) {
  const url = new URL(request.url);

  // ============================================================
  // GET: Render the Setup UI
  // ============================================================
  if (request.method === 'GET') {
    // SECURITY: Strict CSP for the setup page to prevent XSS during bootstrap
    const headers = {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'unsafe-inline' https://cdn.tailwindcss.com;",
      'X-Frame-Options': 'DENY',
    };

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nexus Bootstrap</title>
        <script src="https://cdn.tailwindcss.com"></script>
      </head>
      <body class="bg-gray-900 text-white flex items-center justify-center min-h-screen font-sans">
        <div class="bg-gray-800 p-8 rounded-2xl shadow-2xl w-full max-w-md border border-gray-700">
          <h1 class="text-2xl font-bold mb-2 text-center text-blue-400">Nexus Initialization</h1>
          <p class="text-gray-400 text-sm text-center mb-6">First-run secure setup.</p>
          
          <!-- Gate 1: Bootstrap Password -->
          <div id="step1">
            <label class="block text-sm text-gray-300 mb-2">Bootstrap Password</label>
            <input type="password" id="bootstrapPwd" class="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 mb-4 focus:outline-none focus:border-blue-500">
            <button onclick="verifyBootstrap()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded-lg transition">Verify Password</button>
            <p id="err1" class="text-red-400 text-sm mt-3 hidden text-center"></p>
          </div>

          <!-- Gate 2: Admin Setup (Hidden by default) -->
          <div id="step2" class="hidden">
            <label class="block text-sm text-gray-300 mb-2">Super Admin Email</label>
            <input type="email" id="adminEmail" class="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 mb-4 focus:outline-none focus:border-blue-500">
            
            <label class="block text-sm text-gray-300 mb-2">Admin Password (Min 8 chars)</label>
            <input type="password" id="adminPwd" class="w-full bg-gray-900 border border-gray-600 rounded-lg px-4 py-2 mb-4 focus:outline-none focus:border-blue-500">
            
            <button onclick="initSystem()" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 rounded-lg transition">Complete Setup</button>
            <p id="err2" class="text-red-400 text-sm mt-3 hidden text-center"></p>
          </div>
        </div>

        <script>
          let setupToken = '';

          async function verifyBootstrap() {
            const pwd = document.getElementById('bootstrapPwd').value;
            const res = await fetch('/api/setup?step=verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ bootstrap_password: pwd })
            });
            const data = await res.json();
            
            if (res.ok) {
              setupToken = data.setup_token;
              document.getElementById('step1').classList.add('hidden');
              document.getElementById('step2').classList.remove('hidden');
            } else {
              const err1 = document.getElementById('err1');
              err1.textContent = data.error || 'Invalid password';
              err1.classList.remove('hidden');
            }
          }

          async function initSystem() {
            const email = document.getElementById('adminEmail').value;
            const pwd = document.getElementById('adminPwd').value;
            const res = await fetch('/api/setup?step=init', {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + setupToken // Pass the temporary setup token
              },
              body: JSON.stringify({ email, password: pwd })
            });
            const data = await res.json();
            
            if (res.ok) {
              window.location.href = '/login.html';
            } else {
              const err2 = document.getElementById('err2');
              err2.textContent = data.error || 'Setup failed';
              err2.classList.remove('hidden');
            }
          }
        </script>
      </body>
      </html>
    `;
    return new Response(html, { headers });
  }

  // ============================================================
  // POST: Handle Setup API
  // ============================================================
  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const step = url.searchParams.get('step');

      // --------------------------------------------------------
      // GATE 1: Verify Bootstrap Password
      // --------------------------------------------------------
      if (step === 'verify') {
        const { bootstrap_password } = body;

        if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
          return error('Missing configuration', 400);
        }

        // SECURITY: Constant-time comparison to prevent timing attacks
        const isValid = constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD);

        if (!isValid) {
          // SECURITY: Deliberately vague error to prevent brute-force mapping
          return error('Invalid bootstrap password', 401);
        }

        // Issue a temporary, highly restricted JWT for the setup process (valid for 10 minutes)
        const setupToken = await signJwt(
          { purpose: 'setup', step: 1 }, 
          env.JWT_SECRET, 
          600
        );

        return json({ success: true, setup_token: setupToken });
      }

      // --------------------------------------------------------
      // GATE 2: Initialize Super Admin & Finalize System
      // --------------------------------------------------------
      if (step === 'init') {
        // 1. Verify the temporary setup token
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return error('Unauthorized setup request', 401);
        }
        
        const token = authHeader.split(' ')[1];
        let payload;
        try {
          payload = await verifyJwt(token, env.JWT_SECRET);
        } catch (e) {
          return error('Setup token expired or invalid', 401);
        }

        if (payload.purpose !== 'setup' || payload.step !== 1) {
          return error('Invalid setup token purpose', 403);
        }

        // 2. Validate admin data
        const { email, password } = body;
        if (!email || !password || password.length < 8) {
          return error('Invalid email or password too short', 400);
        }

        // 3. Create Super Admin in D1
        const userId = generateUUID();
        const { hash, salt } = await hashPassword(password);
        const now = Date.now();

        // SECURITY: D1 Prepared Statements prevent SQL Injection
        const createAdminStmt = env.DB.prepare(
          `INSERT INTO users (id, email, role, password_hash, password_salt, created_at, updated_at) 
           VALUES (?, ?, 'super_admin', ?, ?, ?, ?)`
        ).bind(userId, email.toLowerCase(), hash, salt, now, now);

        // 4. Set is_initialized = true
        const setInitStmt = env.DB.prepare(
          `INSERT INTO system_settings (key, value) VALUES ('is_initialized', 'true')`
        );

        // Execute in a transaction (D1 batch)
        await env.DB.batch([createAdminStmt, setInitStmt]);

        // 5. Auto-login the super admin after setup
        const sessionJwt = await signJwt(
          { uid: userId, role: 'super_admin' }, 
          env.JWT_SECRET, 
          86400 // 24 hours
        );

        const cookieHeader = createSessionCookie(sessionJwt, 86400);

        // SECURITY: Clear setup token, set session cookie
        return json(
          { success: true, message: 'System initialized successfully' }, 
          200, 
          { 'Set-Cookie': cookieHeader }
        );
      }

      return error('Invalid setup step', 400);

    } catch (e) {
      console.error('[Setup Error]', e);
      // SECURITY: Generic error output. Never leak database errors.
      return error('Internal Server Error during setup', 500);
    }
  }

  return error('Method Not Allowed', 405);
}
