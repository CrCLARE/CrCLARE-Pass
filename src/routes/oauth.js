// ============================================================
// Nexus - GitHub OAuth 2.0 Flow
// SECURITY: Strictly uses state parameter to prevent CSRF.
// ============================================================

import { json, error, redirect } from '../utils/response.js';
import { signJwt, verifyJwt, createSessionCookie } from '../services/jwt.js';
import { generateUUID } from '../services/crypto.js'; // Helper to generate UUIDs

export async function handleGithubOAuth(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 1. Initiate OAuth Flow (/api/oauth/github)
  if (path === '/api/oauth/github') {
    // SECURITY: Generate a random state string to prevent CSRF
    const state = crypto.randomUUID();
    
    // Store state in an HttpOnly cookie (valid for 10 mins)
    const stateCookie = `nexus_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`;
    
    const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
    githubAuthUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    githubAuthUrl.searchParams.set('redirect_uri', `${url.origin}/api/oauth/github/callback`);
    githubAuthUrl.searchParams.set('state', state);
    githubAuthUrl.searchParams.set('scope', 'read:user user:email');

    return new Response(null, {
      status: 302,
      headers: {
        'Location': githubAuthUrl.toString(),
        'Set-Cookie': stateCookie
      }
    });
  }

  // 2. Callback from GitHub (/api/oauth/github/callback)
  if (path === '/api/oauth/github/callback') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    
    // SECURITY: Extract stored state from cookie
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/nexus_oauth_state=([^;]+)/);
    const storedState = match ? match[1] : null;

    // SECURITY: Validate state to prevent CSRF
    if (!state || !storedState || state !== storedState) {
      return error('ERR_INVALID_STATE', 'CSRF validation failed. Invalid state parameter.', 403);
    }

    if (!code) return error('ERR_NO_CODE', 'Authorization code missing', 400);

    // 3. Exchange code for access token
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code: code,
        redirect_uri: `${url.origin}/api/oauth/github/callback`
      })
    });
    
    const tokenData = await tokenRes.json();
    if (tokenData.error) return error('ERR_OAUTH_TOKEN', tokenData.error_description || 'Failed to get token', 400);

    const accessToken = tokenData.access_token;

    // 4. Fetch user info from GitHub
    const userRes = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${accessToken}`, 'User-Agent': 'Nexus-SSO' }
    });
    const githubUser = await userRes.json();
    
    // Fetch primary email if not public
    let email = githubUser.email;
    if (!email) {
      const emailRes = await fetch('https://api.github.com/user/emails', {
        headers: { 'Authorization': `Bearer ${accessToken}`, 'User-Agent': 'Nexus-SSO' }
      });
      const emails = await emailRes.json();
      const primary = emails.find(e => e.primary && e.verified);
      if (primary) email = primary.email;
    }

    if (!email) return error('ERR_NO_EMAIL', 'Could not retrieve verified email from GitHub', 400);

    // 5. Database Operations (Check if user exists, bind, or create)
    // For V1.0, we check if OAuth account exists.
    const existingOAuth = await env.DB.prepare(
      "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = ?"
    ).bind(githubUser.id.toString()).first();

    let userId;
    if (existingOAuth) {
      userId = existingOAuth.user_id;
    } else {
      // Check if user with this email exists (account linking)
      const existingUser = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
      
      if (existingUser) {
        // Bind existing user to GitHub
        userId = existingUser.id;
        await env.DB.prepare(
          "INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, 'github', ?, ?)"
        ).bind(generateUUID(), userId, githubUser.id.toString(), Date.now()).run();
      } else {
        // Create new user
        userId = generateUUID();
        const now = Date.now();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO users (id, email, role, created_at, updated_at) VALUES (?, ?, 'user', ?, ?)").bind(userId, email, now, now),
          env.DB.prepare("INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, 'github', ?, ?)").bind(generateUUID(), userId, githubUser.id.toString(), now)
        ]);
      }
    }

    // 6. Issue Session Cookie and Redirect to Frontend
    const sessionJwt = await signJwt({ uid: userId, role: 'user' }, env.JWT_SECRET, 86400 * 7);
    const cookieHeaderOut = createSessionCookie(sessionJwt, 86400 * 7);

    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/uc.html', // Redirect to User Center
        'Set-Cookie': cookieHeaderOut
      }
    });
  }
}
