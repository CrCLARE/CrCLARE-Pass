// ============================================================
// Nexus - Public Configuration API
// Exposes non-sensitive configuration for the frontend.
// ============================================================

import { json } from '../utils/response.js';

export async function getPublicConfig(env) {
  try {
    // SECURITY: Only fetch specific public keys.
    const keys = ['site_name', 'site_logo', 'enabled_oauths', 'captcha_provider', 'turnstile_site_key', 'geetest_captcha_id', 'recaptcha_site_key'];
    const placeholders = keys.map(() => '?').join(',');
    
    const stmt = env.DB.prepare(
      `SELECT key, value FROM system_settings WHERE key IN (${placeholders})`
    ).bind(...keys);
    
    const results = await stmt.all();
    
    // Defaults if not configured
    const config = {
      siteName: 'Nexus',
      siteLogo: '',
      enabledOAuths: [], 
      captchaProvider: 'none', // 'none' | 'turnstile' | 'geetest' | 'recaptcha'
      captchaSiteKey: ''
    };

    if (results && results.results) {
      const settings = {};
      results.results.forEach(row => settings[row.key] = row.value);

      if (settings.site_name) config.siteName = settings.site_name;
      if (settings.site_logo) config.siteLogo = settings.site_logo;
      
      // OAuth array
      if (settings.enabled_oauths) {
        try {
          // Filter to only allow GitHub in V1.0
          const oauths = JSON.parse(settings.enabled_oauths);
          config.enabledOAuths = oauths.includes('github') ? ['github'] : [];
        } catch (e) {}
      }

      // Captcha Config
      if (settings.captcha_provider && settings.captcha_provider !== 'none') {
        config.captchaProvider = settings.captcha_provider;
        if (config.captchaProvider === 'turnstile') config.captchaSiteKey = settings.turnstile_site_key;
        if (config.captchaProvider === 'geetest') config.captchaSiteKey = settings.geetest_captcha_id;
        if (config.captchaProvider === 'recaptcha') config.captchaSiteKey = settings.recaptcha_site_key;
      }
    }

    // Cache for 60 seconds
    return json(config, 200, { 'Cache-Control': 'public, max-age=60' });
  } catch (e) {
    console.error('[Config API] Error:', e);
    return json({ error: 'Internal Server Error' }, 500);
  }
}
