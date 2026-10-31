// ============================================================
// Nexus - Authentication Middleware
// SECURITY: Extracts JWT from HttpOnly cookie or Authorization header,
// verifies signature, and enforces Role-Based Access Control (RBAC).
// ============================================================

import { verifyJwt } from '../services/jwt.js';
import { error } from '../utils/response.js';

export async function getAuthenticatedUser(request, env) {
  // 1. Try to get token from HttpOnly Cookie (for web UI)
  let token = null;
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/nexus_session=([^;]+)/);
  if (match) token = match[1];

  // 2. Fallback to Authorization Header (for API clients/SDK)
  if (!token) {
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }
  }

  if (!token) return null;

  try {
    const payload = await verifyJwt(token, env.JWT_SECRET);
    if (!payload || !payload.uid) return null;
    
    // Fetch fresh user data to check if banned or role changed
    const user = await env.DB.prepare(
      "SELECT id, email, role, status FROM users WHERE id = ?"
    ).bind(payload.uid).first();

    if (!user || user.status === 'banned') return null;
    
    return user;
  } catch (e) {
    return null;
  }
}

// Middleware for Admin routes
export async function requireAdmin(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    return { authorized: false, response: error('ERR_UNAUTHORIZED', 'Authentication required', 401) };
  }
  
  if (user.role !== 'admin' && user.role !== 'super_admin') {
    return { authorized: false, response: error('ERR_FORBIDDEN', 'Admin access required', 403) };
  }
  
  return { authorized: true, user };
}
