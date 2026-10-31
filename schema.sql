-- ============================================================
-- Nexus (CrCLARE Identity Hub) - D1 Database Schema
-- SECURITY: All passwords and recovery codes must be hashed
-- before insertion. Never store plaintext secrets.
-- ============================================================

-- System Settings: Used for Bootstrap state and dynamic configs
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL -- Can be plaintext (e.g., 'is_initialized') or WebCrypto encrypted JSON
);

-- Users: Core identity table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, -- UUID v4
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', -- 'user', 'admin', 'super_admin'
    password_hash TEXT, -- Nullable if user strictly uses Passkey
    password_salt TEXT,
    totp_secret TEXT, -- Encrypted TOTP secret
    app_enabled INTEGER DEFAULT 0, -- 1 if Advanced Protection Program is active
    created_at INTEGER NOT NULL, -- Unix timestamp in milliseconds
    updated_at INTEGER NOT NULL
);

-- Passkeys (WebAuthn): Hardware security keys / Biometrics
CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT UNIQUE NOT NULL, -- Base64URL encoded
    public_key TEXT NOT NULL, -- Base64URL encoded COSE key
    sign_count INTEGER NOT NULL DEFAULT 0, -- Anti-cloning counter
    device_name TEXT, -- e.g., 'YubiKey 5C', 'MacBook Pro'
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- OAuth Accounts: Third-party logins (GitHub, Google, etc.)
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL, -- e.g., 'github', 'google'
    provider_user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Recovery Codes: For Advanced Protection Program (APP) lockout recovery
CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL, -- SECURITY: Hash these! Never store plaintext.
    used INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance and security (prevent full table scans)
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_user_id);
