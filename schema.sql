-- ============================================================
-- Nexus (CrCLARE Identity Hub) - D1 Database Schema
-- SECURITY: All passwords must be hashed before insertion. 
-- Never store plaintext secrets.
-- ============================================================

-- 1. System Settings (For Bootstrap, dynamic configs, and legal docs)
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 2. Users (Core Identity)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', -- 'user', 'admin', 'super_admin'
    password_hash TEXT,
    password_salt TEXT,
    totp_secret TEXT,
    app_enabled INTEGER DEFAULT 0, -- Advanced Protection Program flag
    status TEXT DEFAULT 'active', -- 'active', 'banned'
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 3. Passkeys (WebAuthn Hardware Keys)
CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    device_name TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. OAuth Accounts (Third-party bindings)
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL, -- 'github', 'google', 'qq', etc.
    provider_user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. Legal Consents (GDPR / Terms of Service tracking)
CREATE TABLE IF NOT EXISTS user_consents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    consented_at INTEGER NOT NULL,
    ip_address TEXT, -- Optional, for legal proof
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 6. Audit Logs (Track critical actions)
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT, -- user_id or admin_id
    action TEXT NOT NULL, -- e.g., 'user.ban', 'settings.update'
    target_id TEXT,
    details TEXT, -- JSON string
    ip_address TEXT,
    created_at INTEGER NOT NULL
);

-- Indexes for performance and security lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);
