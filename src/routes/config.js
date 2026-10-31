// ============================================================
// Nexus - Public Configuration API
// Exposes non-sensitive configuration for the frontend.
// ============================================================

import { json } from '../utils/response.js';

export async function getPublicConfig(env) {
  try {
    // SECURITY: Only fetch specific public keys.
    const keys = ['site_name', 'site_logo', 'enabled_oauths', 'captcha_provider', 'turnstile_site_key', 'allow_uc_export', 'terms_version'];
    const placeholders = keys.map(() => '?').join(',');
    
    const stmt = env.DB.prepare(`SELECT key, value FROM system_settings WHERE key IN (${placeholders})`).bind(...keys);
    const results = await stmt.all();
    
    const config = {
      siteName: 'Nexus',
      siteLogo: '',
      enabledOAuths: [], 
      captchaProvider: 'none', 
      captchaSiteKey: '',
      allow_uc_export: true,
      termsVersion: 'v1.0'
    };

    if (results && results.results) {
      const settings = {};
      results.results.forEach(row => settings[row.key] = row.value);

      if (settings.site_name) config.siteName = settings.site_name;
      if (settings.site_logo) config.siteLogo = settings.site_logo;
      if (settings.allow_uc_export) config.allow_uc_export = settings.allow_uc_export === 'true';
      if (settings.terms_version) config.termsVersion = settings.terms_version;
      
      if (settings.enabled_oauths) {
        try { config.enabledOAuths = JSON.parse(settings.enabled_oauths); } catch (e) {}
      }

      if (settings.captcha_provider && settings.captcha_provider !== 'none') {
        config.captchaProvider = settings.captcha_provider;
        if (config.captchaProvider === 'turnstile') config.captchaSiteKey = settings.turnstile_site_key;
      }
    }

    return json(config, 200, { 'Cache-Control': 'public, max-age=60' });
  } catch (e) {
    console.error('[Config API] Error:', e);
    return json({ error: 'Internal Server Error' }, 500);
  }
}
