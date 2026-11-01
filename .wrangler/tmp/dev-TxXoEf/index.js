var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-N7nbUP/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
__name(checkURL, "checkURL");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// src/config/constants.js
var SECURITY_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
};

// src/utils/response.js
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders }
  });
}
__name(json, "json");
function error(code, message = "An error occurred", status = 400, extraHeaders = {}) {
  return json({ error: { code, message } }, status, extraHeaders);
}
__name(error, "error");

// src/utils/crypto.js
function generateUUID() {
  return crypto.randomUUID();
}
__name(generateUUID, "generateUUID");
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const len = Math.max(a.length, b.length);
  let diff = 0;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}
__name(constantTimeEqual, "constantTimeEqual");
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 1e5, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return {
    hash: Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join(""),
    salt: Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("")
  };
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, storedHash, storedSaltHex) {
  const enc = new TextEncoder();
  const salt = new Uint8Array(storedSaltHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 1e5, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const hash = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return constantTimeEqual(hash, storedHash);
}
__name(verifyPassword, "verifyPassword");

// src/utils/encoder.js
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
__name(bufferToBase64Url, "bufferToBase64Url");
function base64UrlToBuffer(base64url) {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
__name(base64UrlToBuffer, "base64UrlToBuffer");

// src/services/jwt.js
var ALGORITHM = { name: "HMAC", hash: "SHA-256" };
async function getCryptoKey(secret) {
  return await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), ALGORITHM, false, ["sign", "verify"]);
}
__name(getCryptoKey, "getCryptoKey");
async function signJwt(payload, secret, ttlSeconds = 3600) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const fullPayload = { ...payload, iat: now, exp: now + ttlSeconds };
  const encodedHeader = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(header)).buffer);
  const encodedPayload = bufferToBase64Url(new TextEncoder().encode(JSON.stringify(fullPayload)).buffer);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  const key = await getCryptoKey(secret);
  const signature = await crypto.subtle.sign(ALGORITHM, key, new TextEncoder().encode(dataToSign));
  return `${dataToSign}.${bufferToBase64Url(signature)}`;
}
__name(signJwt, "signJwt");
async function verifyJwt(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const dataToSign = `${encodedHeader}.${encodedPayload}`;
  const key = await getCryptoKey(secret);
  const signatureBuffer = base64UrlToBuffer(encodedSignature);
  const isValid = await crypto.subtle.verify(ALGORITHM, key, signatureBuffer, new TextEncoder().encode(dataToSign));
  if (!isValid) throw new Error("Invalid signature");
  const payload = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(encodedPayload)));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1e3)) throw new Error("Token expired");
  return payload;
}
__name(verifyJwt, "verifyJwt");
function createSessionCookie(token, ttlSeconds) {
  return `nexus_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${ttlSeconds}`;
}
__name(createSessionCookie, "createSessionCookie");

// src/routes/setup.js
async function handleSetupAPI(request, env) {
  if (request.method !== "POST") {
    return error("ERR_METHOD", "Method not allowed", 405);
  }
  try {
    const url = new URL(request.url);
    const step = url.searchParams.get("step");
    const body = await request.json();
    if (step === "verify") {
      const { bootstrap_password } = body;
      if (!bootstrap_password || !env.INIT_ADMIN_PASSWORD) {
        return error("ERR_MISSING", "Missing configuration", 400);
      }
      const isPasswordValid = constantTimeEqual(bootstrap_password, env.INIT_ADMIN_PASSWORD);
      if (!isPasswordValid) {
        return error("ERR_INVALID_PWD", "Invalid bootstrap password", 401);
      }
      const isInit = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'is_initialized'").first();
      if (isInit && isInit.value === "true") {
        return error("ERR_ALREADY_INIT", "System already initialized", 403);
      }
      const setupToken = await signJwt({ purpose: "setup" }, env.JWT_SECRET, 600);
      return json({ success: true, setup_token: setupToken });
    }
    if (step === "init") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return error("ERR_UNAUTHORIZED", "Missing setup token", 401);
      }
      const token = authHeader.split(" ")[1];
      let payload;
      try {
        payload = await verifyJwt(token, env.JWT_SECRET);
      } catch (e) {
        return error("ERR_EXPIRED", "Setup token expired or invalid", 401);
      }
      if (payload.purpose !== "setup") {
        return error("ERR_FORBIDDEN", "Invalid token purpose", 403);
      }
      const { email, password } = body;
      if (!email || !password || password.length < 8) {
        return error("ERR_INVALID_INPUT", "Invalid email or password too short", 400);
      }
      const userId = generateUUID();
      const { hash, salt } = await hashPassword(password);
      const now = Date.now();
      const createAdmin = env.DB.prepare(
        `INSERT INTO users (id, email, role, password_hash, password_salt, status, created_at, updated_at) 
         VALUES (?, ?, 'super_admin', ?, ?, 'active', ?, ?)`
      ).bind(userId, email.toLowerCase(), hash, salt, now, now);
      const setInit = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('is_initialized', 'true', ?)`
      ).bind(now);
      const setSiteName = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('site_name', 'Nexus', ?)`
      ).bind(now);
      const setTermsVersion = env.DB.prepare(
        `INSERT INTO system_settings (key, value, updated_at) VALUES ('terms_version', 'v1.0', ?)`
      ).bind(now);
      await env.DB.batch([createAdmin, setInit, setSiteName, setTermsVersion]);
      const sessionJwt = await signJwt({ uid: userId, role: "super_admin" }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);
      return json(
        { success: true, message: "System initialized" },
        200,
        { "Set-Cookie": cookieHeader }
      );
    }
    return error("ERR_INVALID_STEP", "Invalid setup step", 400);
  } catch (e) {
    console.error("[Setup Error]", e);
    return error("ERR_INTERNAL", "Internal Server Error during setup", 500);
  }
}
__name(handleSetupAPI, "handleSetupAPI");

// src/routes/config.js
async function getPublicConfig(env) {
  try {
    const keys = ["site_name", "site_logo", "enabled_oauths", "captcha_provider", "turnstile_site_key", "allow_uc_export", "terms_version"];
    const placeholders = keys.map(() => "?").join(",");
    const stmt = env.DB.prepare(`SELECT key, value FROM system_settings WHERE key IN (${placeholders})`).bind(...keys);
    const results = await stmt.all();
    const config = {
      siteName: "Nexus",
      siteLogo: "",
      enabledOAuths: [],
      captchaProvider: "none",
      captchaSiteKey: "",
      allow_uc_export: true,
      termsVersion: "v1.0"
    };
    if (results && results.results) {
      const settings = {};
      results.results.forEach((row) => settings[row.key] = row.value);
      if (settings.site_name) config.siteName = settings.site_name;
      if (settings.site_logo) config.siteLogo = settings.site_logo;
      if (settings.allow_uc_export) config.allow_uc_export = settings.allow_uc_export === "true";
      if (settings.terms_version) config.termsVersion = settings.terms_version;
      if (settings.enabled_oauths) {
        try {
          config.enabledOAuths = JSON.parse(settings.enabled_oauths);
        } catch (e) {
        }
      }
      if (settings.captcha_provider && settings.captcha_provider !== "none") {
        config.captchaProvider = settings.captcha_provider;
        if (config.captchaProvider === "turnstile") config.captchaSiteKey = settings.turnstile_site_key;
      }
    }
    return json(config, 200, { "Cache-Control": "public, max-age=60" });
  } catch (e) {
    console.error("[Config API] Error:", e);
    return json({ error: "Internal Server Error" }, 500);
  }
}
__name(getPublicConfig, "getPublicConfig");

// src/services/email.js
async function sendEmail(env, to, subject, htmlBody) {
  if (!env.RESEND_API_KEY) {
    console.warn("[Email] RESEND_API_KEY is not set. Email will not be sent.");
    return { success: false, error: "Email provider not configured" };
  }
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || "Nexus Auth <noreply@yourdomain.com>",
        // Configure this in env
        to: [to],
        subject,
        html: htmlBody
      })
    });
    const data = await response.json();
    if (!response.ok) {
      console.error("[Email] Failed to send:", data);
      return { success: false, error: data.message };
    }
    return { success: true, id: data.id };
  } catch (e) {
    console.error("[Email] Network Error:", e);
    return { success: false, error: "Network error while sending email" };
  }
}
__name(sendEmail, "sendEmail");
function generateVerifyEmailHtml(code, siteName = "Nexus") {
  return `
    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; background: #18181b; color: #e4e4e7; padding: 40px; border-radius: 12px;">
      <h2 style="color: #93c5fd; text-align: center;">${siteName}</h2>
      <p style="font-size: 16px;">Hello,</p>
      <p style="font-size: 16px;">You recently requested to verify your email address. Please use the following 6-digit code to complete the process:</p>
      
      <div style="text-align: center; margin: 30px 0;">
        <span style="display: inline-block; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 15px 25px; background: #27272a; border-radius: 8px; color: #ffffff;">
          ${code}
        </span>
      </div>
      
      <p style="font-size: 14px; color: #a1a1aa;">This code will expire in 15 minutes. If you did not request this, please ignore this email.</p>
      <hr style="border: none; border-top: 1px solid #3f3f46; margin: 30px 0;" />
      <p style="font-size: 12px; text-align: center; color: #71717a;">
        Powered by <a href="https://github.com/CrCLARE/Nexus" style="color: #60a5fa; text-decoration: none;">Nexus</a>
      </p>
    </div>
  `;
}
__name(generateVerifyEmailHtml, "generateVerifyEmailHtml");

// src/routes/auth.js
async function verifyCaptcha(env, token) {
  const provider = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'captcha_provider'").first();
  if (!provider || provider.value === "none") return true;
  if (!token) return false;
  try {
    if (provider.value === "turnstile") {
      const secret = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'turnstile_secret_key'").first();
      if (!secret) return false;
      const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `secret=${secret.value}&response=${token}`
      });
      const data = await res.json();
      return data.success;
    }
    return false;
  } catch (e) {
    console.error("[CAPTCHA Error]", e);
    return false;
  }
}
__name(verifyCaptcha, "verifyCaptcha");
async function handleAuthAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/api/auth/login" && request.method === "POST") {
    try {
      const body = await request.json();
      const { email, password, captcha_token } = body;
      if (!email || !password) {
        return error("ERR_INVALID_INPUT", "Email and password are required", 400);
      }
      const isCaptchaValid = await verifyCaptcha(env, captcha_token);
      if (!isCaptchaValid) {
        return error("ERR_CAPTCHA_FAILED", "Human verification failed", 400);
      }
      const user = await env.DB.prepare(
        "SELECT id, email, role, password_hash, password_salt, status FROM users WHERE email = ?"
      ).bind(email.toLowerCase()).first();
      if (!user) {
        return error("ERR_INVALID_CREDENTIALS", "Invalid email or password", 401);
      }
      if (user.status === "banned") {
        return error("ERR_FORBIDDEN", "Account is banned", 403);
      }
      if (user.status === "pending") {
        return error("ERR_PENDING_VERIFY", "Email not verified. Please check your inbox.", 403);
      }
      const isValid = await verifyPassword(password, user.password_hash, user.password_salt);
      if (!isValid) {
        return error("ERR_INVALID_CREDENTIALS", "Invalid email or password", 401);
      }
      const sessionJwt = await signJwt({ uid: user.id, role: user.role }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);
      return json(
        { success: true, user: { id: user.id, email: user.email, role: user.role } },
        200,
        { "Set-Cookie": cookieHeader }
      );
    } catch (e) {
      console.error("[Login Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error", 500);
    }
  }
  if (path === "/api/auth/register" && request.method === "POST") {
    try {
      const body = await request.json();
      const { email, password, agreed_to_terms, terms_version, captcha_token } = body;
      if (!email || !password) {
        return error("ERR_INVALID_INPUT", "Email and password are required", 400);
      }
      if (!agreed_to_terms) {
        return error("ERR_TERMS_REQUIRED", "You must agree to the Terms of Service", 400);
      }
      const currentTerms = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'terms_version'").first();
      if (currentTerms && terms_version !== currentTerms.value) {
        return error("ERR_TERMS_UPDATE_REQUIRED", "Terms of Service have been updated", 403);
      }
      const isCaptchaValid = await verifyCaptcha(env, captcha_token);
      if (!isCaptchaValid) {
        return error("ERR_CAPTCHA_FAILED", "Human verification failed", 400);
      }
      const existingUser = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
      if (existingUser) {
        return error("ERR_EMAIL_EXISTS", "Email is already registered", 409);
      }
      const { hash, salt } = await hashPassword(password);
      const userId = generateUUID();
      const now = Date.now();
      const reqEmailSetting = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'require_email_verify'").first();
      const requireVerify = reqEmailSetting && reqEmailSetting.value === "true";
      const insertStmt = env.DB.prepare(
        "INSERT INTO users (id, email, role, password_hash, password_salt, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(userId, email.toLowerCase(), "user", hash, salt, requireVerify ? "pending" : "active", now, now);
      await insertStmt.run();
      await env.DB.prepare(
        "INSERT INTO user_consents (id, user_id, terms_version, privacy_version, consented_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(generateUUID(), userId, terms_version, terms_version, now).run();
      if (requireVerify) {
        const code = Math.floor(1e5 + Math.random() * 9e5).toString();
        await env.KV.put(`verify_code:${email.toLowerCase()}`, code, { expirationTtl: 900 });
        const html = generateVerifyEmailHtml(code);
        await sendEmail(env, email, "Verify your email - Nexus", html);
        return json({ success: true, require_verify: true, email }, 200);
      } else {
        const sessionJwt = await signJwt({ uid: userId, role: "user" }, env.JWT_SECRET, 86400 * 7);
        const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);
        return json(
          { success: true, require_verify: false, user: { id: userId, email, role: "user" } },
          200,
          { "Set-Cookie": cookieHeader }
        );
      }
    } catch (e) {
      console.error("[Register Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error", 500);
    }
  }
  if (path === "/api/auth/verify-email" && request.method === "POST") {
    try {
      const body = await request.json();
      const { email, code } = body;
      if (!email || !code) {
        return error("ERR_INVALID_INPUT", "Email and code are required", 400);
      }
      const normalizedEmail = email.toLowerCase();
      const savedCode = await env.KV.get(`verify_code:${normalizedEmail}`);
      if (!savedCode) {
        return error("ERR_CODE_EXPIRED", "Verification code expired or invalid", 400);
      }
      if (!constantTimeEqual(savedCode, code)) {
        return error("ERR_INVALID_CODE", "Incorrect verification code", 401);
      }
      const updateResult = await env.DB.prepare(
        "UPDATE users SET status = 'active', updated_at = ? WHERE email = ? AND status = 'pending'"
      ).bind(Date.now(), normalizedEmail).run();
      if (updateResult.meta.changes === 0) {
        return error("ERR_UPDATE_FAILED", "User not found or already verified", 400);
      }
      await env.KV.delete(`verify_code:${normalizedEmail}`);
      const user = await env.DB.prepare("SELECT id, role FROM users WHERE email = ?").bind(normalizedEmail).first();
      const sessionJwt = await signJwt({ uid: user.id, role: user.role }, env.JWT_SECRET, 86400 * 7);
      const cookieHeader = createSessionCookie(sessionJwt, 86400 * 7);
      return json(
        { success: true, message: "Email verified successfully" },
        200,
        { "Set-Cookie": cookieHeader }
      );
    } catch (e) {
      console.error("[Verify Email Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error", 500);
    }
  }
  if (path === "/api/auth/resend-verification" && request.method === "POST") {
    try {
      const body = await request.json();
      const { email } = body;
      if (!email) return error("ERR_INVALID_INPUT", "Email is required", 400);
      const normalizedEmail = email.toLowerCase();
      const limitKey = `resend_limit:${normalizedEmail}`;
      const isLimited = await env.KV.get(limitKey);
      if (isLimited) {
        return error("ERR_RATE_LIMITED", "Please wait 60 seconds before requesting a new code", 429);
      }
      const user = await env.DB.prepare("SELECT id FROM users WHERE email = ? AND status = 'pending'").bind(normalizedEmail).first();
      if (!user) {
        return json({ success: true, message: "If the account exists, a code has been sent" });
      }
      const code = Math.floor(1e5 + Math.random() * 9e5).toString();
      await env.KV.put(`verify_code:${normalizedEmail}`, code, { expirationTtl: 900 });
      await env.KV.put(limitKey, "1", { expirationTtl: 60 });
      const html = generateVerifyEmailHtml(code);
      await sendEmail(env, email, "Verify your email - Nexus", html);
      return json({ success: true, message: "Verification code resent" });
    } catch (e) {
      console.error("[Resend Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error", 500);
    }
  }
  if (path === "/api/auth/logout" && request.method === "POST") {
    const cookieHeader = "nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    return json({ success: true, message: "Logged out" }, 200, { "Set-Cookie": cookieHeader });
  }
  return error("ERR_NOT_FOUND", "Auth route not found", 404);
}
__name(handleAuthAPI, "handleAuthAPI");

// src/routes/oauth.js
async function handleOAuth(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/api/oauth/github") {
    const state = crypto.randomUUID();
    const stateCookie = `nexus_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`;
    const githubAuthUrl = new URL("https://github.com/login/oauth/authorize");
    githubAuthUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    githubAuthUrl.searchParams.set("redirect_uri", `${url.origin}/api/oauth/github/callback`);
    githubAuthUrl.searchParams.set("state", state);
    githubAuthUrl.searchParams.set("scope", "read:user user:email");
    return new Response(null, {
      status: 302,
      headers: {
        "Location": githubAuthUrl.toString(),
        "Set-Cookie": stateCookie
      }
    });
  }
  if (path === "/api/oauth/github/callback") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookieHeader = request.headers.get("Cookie") || "";
    const match = cookieHeader.match(/nexus_oauth_state=([^;]+)/);
    const storedState = match ? match[1] : null;
    if (!state || !storedState || state !== storedState) {
      return error("ERR_INVALID_STATE", "CSRF validation failed. Invalid state parameter.", 403);
    }
    if (!code) return error("ERR_NO_CODE", "Authorization code missing", 400);
    try {
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "Accept": "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: `${url.origin}/api/oauth/github/callback`
        })
      });
      const tokenData = await tokenRes.json();
      if (tokenData.error) {
        return error("ERR_OAUTH_TOKEN", tokenData.error_description || "Failed to get token", 400);
      }
      const accessToken = tokenData.access_token;
      const userRes = await fetch("https://api.github.com/user", {
        headers: { "Authorization": `Bearer ${accessToken}`, "User-Agent": "Nexus-SSO" }
      });
      const githubUser = await userRes.json();
      let email = githubUser.email;
      if (!email) {
        const emailRes = await fetch("https://api.github.com/user/emails", {
          headers: { "Authorization": `Bearer ${accessToken}`, "User-Agent": "Nexus-SSO" }
        });
        const emails = await emailRes.json();
        const primary = emails.find((e) => e.primary && e.verified);
        if (primary) email = primary.email;
      }
      if (!email) {
        return error("ERR_NO_EMAIL", "Could not retrieve verified email from GitHub", 400);
      }
      const existingOAuth = await env.DB.prepare(
        "SELECT user_id FROM oauth_accounts WHERE provider = 'github' AND provider_user_id = ?"
      ).bind(githubUser.id.toString()).first();
      let userId;
      if (existingOAuth) {
        userId = existingOAuth.user_id;
      } else {
        const existingUser = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email.toLowerCase()).first();
        if (existingUser) {
          userId = existingUser.id;
          await env.DB.prepare(
            "INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, 'github', ?, ?)"
          ).bind(generateUUID(), userId, githubUser.id.toString(), Date.now()).run();
        } else {
          userId = generateUUID();
          const now = Date.now();
          await env.DB.batch([
            env.DB.prepare("INSERT INTO users (id, email, role, status, created_at, updated_at) VALUES (?, ?, 'user', 'active', ?, ?)").bind(userId, email.toLowerCase(), now, now),
            env.DB.prepare("INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, 'github', ?, ?)").bind(generateUUID(), userId, githubUser.id.toString(), now)
          ]);
        }
      }
      const sessionJwt = await signJwt({ uid: userId, role: "user" }, env.JWT_SECRET, 86400 * 7);
      const cookieHeaderOut = createSessionCookie(sessionJwt, 86400 * 7);
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/uc.html",
          "Set-Cookie": cookieHeaderOut
        }
      });
    } catch (e) {
      console.error("[OAuth Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error during OAuth", 500);
    }
  }
  return error("ERR_NOT_FOUND", "OAuth route not found", 404);
}
__name(handleOAuth, "handleOAuth");

// src/middleware/auth.js
async function getAuthenticatedUser(request, env) {
  let token = null;
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/nexus_session=([^;]+)/);
  if (match) token = match[1];
  if (!token) {
    const authHeader = request.headers.get("Authorization");
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }
  }
  if (!token) return null;
  try {
    const payload = await verifyJwt(token, env.JWT_SECRET);
    if (!payload || !payload.uid) return null;
    const user = await env.DB.prepare(
      "SELECT id, email, role, status FROM users WHERE id = ?"
    ).bind(payload.uid).first();
    if (!user || user.status === "banned") return null;
    return user;
  } catch (e) {
    return null;
  }
}
__name(getAuthenticatedUser, "getAuthenticatedUser");
async function requireAdmin(request, env) {
  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    return { authorized: false, response: error("ERR_UNAUTHORIZED", "Authentication required", 401) };
  }
  if (user.role !== "admin" && user.role !== "super_admin") {
    return { authorized: false, response: error("ERR_FORBIDDEN", "Admin access required", 403) };
  }
  return { authorized: true, user };
}
__name(requireAdmin, "requireAdmin");

// src/routes/admin.js
var ALLOWED_SETTINGS = [
  "site_name",
  "site_logo",
  "powered_by_text",
  "require_email_verify",
  "allow_uc_export",
  "pwd_min_length",
  "pwd_require_strong",
  "captcha_provider",
  "turnstile_site_key",
  "enabled_oauths",
  "github_client_id",
  "github_client_secret",
  "enable_cookie_banner"
];
async function handleAdminAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const auth = await requireAdmin(request, env);
  if (!auth.authorized) return auth.response;
  if (path === "/api/admin/stats" && request.method === "GET") {
    try {
      const userCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
      const oauthCount = await env.DB.prepare("SELECT COUNT(*) as count FROM oauth_accounts").first();
      const appCount = { count: 0 };
      return json({
        users: userCount.count || 0,
        oauths: oauthCount.count || 0,
        apps: appCount.count
      });
    } catch (e) {
      console.error("[Admin API] Stats Error:", e);
      return error("ERR_DB", "Failed to fetch stats", 500);
    }
  }
  if (path === "/api/admin/users" && request.method === "GET") {
    try {
      const users = await env.DB.prepare(
        "SELECT id, email, role, status, created_at FROM users ORDER BY created_at DESC LIMIT 50"
      ).all();
      return json(users.results || []);
    } catch (e) {
      console.error("[Admin API] Users Error:", e);
      return json({ error: "Failed to fetch users" }, 500);
    }
  }
  if (path === "/api/admin/settings" && request.method === "GET") {
    try {
      const results = await env.DB.prepare("SELECT key, value FROM system_settings").all();
      const settings = {};
      if (results.results) {
        results.results.forEach((row) => settings[row.key] = row.value);
      }
      if (settings.github_client_secret) {
        settings.github_client_secret = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
      }
      return json(settings);
    } catch (e) {
      console.error("[Admin API] Settings Fetch Error:", e);
      return error("ERR_DB", "Failed to fetch settings", 500);
    }
  }
  if (path === "/api/admin/settings" && request.method === "POST") {
    try {
      const body = await request.json();
      const statements = [];
      const now = Date.now();
      for (const [key, value] of Object.entries(body)) {
        if (!ALLOWED_SETTINGS.includes(key)) continue;
        if (key === "github_client_secret" && value === "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022") continue;
        statements.push(
          env.DB.prepare(`
            INSERT INTO system_settings (key, value, updated_at) 
            VALUES (?, ?, ?) 
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
          `).bind(key, String(value), now)
        );
      }
      if (statements.length > 0) {
        await env.DB.batch(statements);
      }
      return json({ success: true, message: "Settings updated" });
    } catch (e) {
      console.error("[Admin API] Settings Update Error:", e);
      return error("ERR_DB", "Failed to update settings", 500);
    }
  }
  return error("ERR_NOT_FOUND", "Admin route not found", 404);
}
__name(handleAdminAPI, "handleAdminAPI");

// src/routes/user.js
async function handleUserAPI(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const user = await getAuthenticatedUser(request, env);
  if (!user) {
    return error("ERR_UNAUTHORIZED", "Authentication required", 401);
  }
  if (path === "/api/user/me" && request.method === "GET") {
    try {
      const profile = await env.DB.prepare(
        "SELECT id, email, role, nickname, app_enabled, created_at FROM users WHERE id = ?"
      ).bind(user.id).first();
      const oauths = await env.DB.prepare(
        "SELECT provider FROM oauth_accounts WHERE user_id = ?"
      ).bind(user.id).all();
      const passkeys = await env.DB.prepare(
        "SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?"
      ).bind(user.id).first();
      const boundOAuths = oauths.results ? oauths.results.map((o) => o.provider) : [];
      return json({
        nexusId: profile.id,
        email: profile.email,
        role: profile.role,
        nickname: profile.nickname || profile.email.split("@")[0],
        // Fallback to email prefix
        appEnabled: profile.app_enabled === 1,
        passkeysCount: passkeys ? passkeys.count : 0,
        createdAt: profile.created_at,
        boundOAuths
      });
    } catch (e) {
      return error("ERR_DB", "Failed to fetch user data", 500);
    }
  }
  if (path === "/api/user/update-profile" && request.method === "POST") {
    try {
      const { nickname } = await request.json();
      if (!nickname || nickname.length > 32) {
        return error("ERR_INVALID_INPUT", "Invalid nickname (Max 32 chars)", 400);
      }
      await env.DB.prepare(
        "UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?"
      ).bind(nickname, Date.now(), user.id).run();
      return json({ success: true, message: "Profile updated" });
    } catch (e) {
      return error("ERR_DB", "Failed to update profile", 500);
    }
  }
  if (path === "/api/user/change-password" && request.method === "POST") {
    try {
      const { oldPassword, newPassword } = await request.json();
      if (!oldPassword || !newPassword || newPassword.length < 8) {
        return error("ERR_INVALID_INPUT", "Invalid password format", 400);
      }
      const dbUser = await env.DB.prepare("SELECT password_hash, password_salt FROM users WHERE id = ?").bind(user.id).first();
      if (dbUser.password_hash) {
        const isValid = await verifyPassword(oldPassword, dbUser.password_hash, dbUser.password_salt);
        if (!isValid) return error("ERR_INVALID_CREDENTIALS", "Incorrect old password", 401);
      }
      const { hash, salt } = await hashPassword(newPassword);
      await env.DB.prepare(
        "UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?"
      ).bind(hash, salt, Date.now(), user.id).run();
      return json({ success: true, message: "Password changed successfully" });
    } catch (e) {
      return error("ERR_DB", "Failed to change password", 500);
    }
  }
  if (path === "/api/user/export" && request.method === "GET") {
    try {
      const allowExport = await env.DB.prepare("SELECT value FROM system_settings WHERE key = 'allow_uc_export'").first();
      if (allowExport && allowExport.value === "false") {
        return error("ERR_FORBIDDEN", "Data export is disabled by administrator", 403);
      }
      const profile = await env.DB.prepare("SELECT id, email, role, nickname, created_at FROM users WHERE id = ?").bind(user.id).first();
      const oauths = await env.DB.prepare("SELECT provider, created_at FROM oauth_accounts WHERE user_id = ?").bind(user.id).all();
      const exportData = {
        export_date: (/* @__PURE__ */ new Date()).toISOString(),
        nexus_id: profile.id,
        email: profile.email,
        nickname: profile.nickname,
        role: profile.role,
        joined_at: profile.created_at,
        connected_accounts: oauths.results || []
      };
      const headers = {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="nexus-export-${profile.id}.json"`
      };
      return new Response(JSON.stringify(exportData, null, 2), { status: 200, headers });
    } catch (e) {
      return error("ERR_DB", "Failed to export data", 500);
    }
  }
  if (path === "/api/user/delete-account" && request.method === "POST") {
    try {
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id).run();
      const cookieHeader = "nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
      return json({ success: true, message: "Account deleted" }, 200, { "Set-Cookie": cookieHeader });
    } catch (e) {
      return error("ERR_DB", "Failed to delete account", 500);
    }
  }
  return error("ERR_NOT_FOUND", "User route not found", 404);
}
__name(handleUserAPI, "handleUserAPI");

// src/index.js
var src_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      let isInitialized = false;
      try {
        const result = await env.DB.prepare(
          "SELECT value FROM system_settings WHERE key = 'is_initialized'"
        ).first();
        isInitialized = result && result.value === "true";
      } catch (e) {
        isInitialized = false;
      }
      if (!isInitialized) {
        if (path === "/api/setup") {
          return handleSetupAPI(request, env);
        }
        if (path.startsWith("/api/")) {
          return error("ERR_NOT_INIT", "System not initialized", 403);
        }
        if (!path.includes(".") && path !== "/setup.html") {
          return Response.redirect(`${url.origin}/setup.html`, 302);
        }
      }
      if (isInitialized && path === "/api/setup") {
        return error("ERR_ALREADY_INIT", "System already initialized", 403);
      }
      if (path.startsWith("/api/")) {
        if (path === "/api/config/public" && request.method === "GET") {
          return getPublicConfig(env);
        }
        if (path.startsWith("/api/auth")) {
          return handleAuthAPI(request, env);
        }
        if (path.startsWith("/api/oauth")) {
          return handleOAuth(request, env);
        }
        if (path.startsWith("/api/admin")) {
          return handleAdminAPI(request, env);
        }
        if (path.startsWith("/api/user")) {
          return handleUserAPI(request, env);
        }
        return error("ERR_NOT_FOUND", "API route not found", 404);
      }
      return env.ASSETS.fetch(request);
    } catch (e) {
      console.error("[Nexus Core Error]", e);
      return error("ERR_SYSTEM_ERROR", "Internal Server Error", 500);
    }
  }
};

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error2 = reduceError(e);
    const body = JSON.stringify(error2);
    const headers = {
      "Content-Type": "application/json",
      "MF-Experimental-Error-Stack": "true"
    };
    const encoded = encodeURIComponent(body);
    if (encoded.length <= 8192) {
      headers["MF-Experimental-Error-Stack-Payload"] = encoded;
    }
    return new Response(body, { status: 500, headers });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-N7nbUP/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-N7nbUP/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
