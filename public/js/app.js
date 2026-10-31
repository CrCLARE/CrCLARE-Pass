// ============================================================
// Nexus - Dynamic Frontend Application Logic
// SECURITY: Uses textContent strictly for DOM injection.
// ============================================================

// Supported OAuth providers mapping
const OAUTH_PROVIDERS = {
  github: {
    name: 'GitHub',
    icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>`
  },
  google: {
    name: 'Google',
    icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>`
  },
  qq: {
    name: 'QQ',
    icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="#60a5fa"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5a2.5 2.5 0 010-5 2.5 2.5 0 010 5z"/></svg>`
  },
  // Add more providers here as needed (microsoft, apple, reddit, discord, facebook)
};

// Global state to store backend config
window.NEXUS_CONFIG = window.NEXUS_CONFIG || {};

export async function initApp() {
  try {
    // Fetch dynamic configuration from backend
    const res = await fetch('/api/config/public');
    const config = await res.json();

    // Save config globally for other functions to access
    window.NEXUS_CONFIG = config;

    // 1. Update Site Name
    const siteNameEl = document.getElementById('site-name');
    if (siteNameEl && config.siteName) {
      siteNameEl.textContent = config.siteName;
      document.title = document.title.replace('Nexus', config.siteName);
    }

    // 2. Update Logo (Supports URL or SVG string)
    const logoImg = document.getElementById('dynamic-logo-img');
    const defaultLogo = document.getElementById('default-logo');
    const logoContainer = document.getElementById('site-logo-container');
    
    if (config.siteLogo && logoImg) {
      // SECURITY: Ensure it's a valid image URL or safe SVG data URI
      if (config.siteLogo.startsWith('data:image/') || config.siteLogo.startsWith('http')) {
        logoImg.src = config.siteLogo;
        logoImg.classList.remove('hidden');
        if (defaultLogo) defaultLogo.classList.add('hidden');
        if (logoContainer) logoContainer.classList.remove('bg-[#93c5fd]');
      }
    }

    // 3. Render OAuth Buttons dynamically
    const oauthContainer = document.getElementById('oauth-container');
    const oauthSection = document.getElementById('oauth-section');
    
    if (config.enabledOAuths && config.enabledOAuths.length > 0) {
      oauthSection.classList.remove('hidden');
      oauthContainer.innerHTML = ''; // Clear skeleton

      config.enabledOAuths.forEach(providerKey => {
        const provider = OAUTH_PROVIDERS[providerKey];
        if (!provider) return;

        const btn = document.createElement('a');
        btn.href = `/api/auth/oauth/${providerKey}`;
        btn.className = "w-full btn-outline text-[14px] flex items-center justify-center gap-2 py-2.5";
        
        // SECURITY: Using innerHTML only with our trusted constant string icon
        btn.innerHTML = `${provider.icon} <span>${provider.name}</span>`;
        
        oauthContainer.appendChild(btn);
      });
    }

    // 4. Update Powered By text
    const poweredByEl = document.getElementById('powered-by-text');
    if (poweredByEl && config.poweredByText) {
      poweredByEl.textContent = config.poweredByText;
    }

  } catch (e) {
    console.error('[App] Failed to load dynamic config:', e);
  }
}

/**
 * Handles the two-step login flow and dynamic Turnstile rendering.
 */
export function setupLoginFlow() {
  const stepEmail = document.getElementById('step-email');
  const stepPassword = document.getElementById('step-password');
  const emailForm = document.getElementById('emailForm');
  const passwordForm = document.getElementById('passwordForm');
  const backBtn = document.getElementById('backToEmail');
  const displayEmail = document.getElementById('display-email');
  const turnstileContainer = document.getElementById('turnstile-container');
  
  let currentEmail = '';
  let turnstileWidgetId = null;

  // Step 1: Proceed to password view
  emailForm.addEventListener('submit', (e) => {
    e.preventDefault();
    currentEmail = document.getElementById('email').value.trim();
    if(!currentEmail) return;

    displayEmail.textContent = currentEmail;
    stepEmail.classList.add('step-hidden');
    stepPassword.classList.remove('step-hidden');
    
    setTimeout(() => document.getElementById('password').focus(), 100);

    // SECURITY: Render Turnstile only if enabled by Admin and SiteKey is provided.
    const config = window.NEXUS_CONFIG;
    if (config.enableTurnstile && config.turnstileSiteKey) {
      turnstileContainer.classList.remove('hidden');
      
      // Render only once
      if (!turnstileWidgetId && window.turnstile) {
        turnstileWidgetId = window.turnstile.render('#turnstile-container', {
          sitekey: config.turnstileSiteKey,
          theme: 'dark',
        });
      }
    } else {
      // Hide container if admin disabled it
      turnstileContainer.classList.add('hidden');
    }
  });

  // Back button logic
  backBtn.addEventListener('click', () => {
    stepPassword.classList.add('step-hidden');
    stepEmail.classList.remove('step-hidden');
    document.getElementById('password').value = '';
    
    // Reset Turnstile if it was rendered
    if(turnstileWidgetId && window.turnstile) {
      window.turnstile.reset(turnstileWidgetId);
    }
  });

  // Step 2: Submit password
  passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('password').value;
    const config = window.NEXUS_CONFIG;
    
    let turnstileToken = '';

    // SECURITY: Only require Turnstile token if Admin enabled it
    if (config.enableTurnstile && config.turnstileSiteKey) {
      turnstileToken = window.turnstile.getResponse(turnstileWidgetId);
      if (!turnstileToken) {
        alert("Please complete the human verification."); 
        return;
      }
    }

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          email: currentEmail, 
          password: password,
          turnstile_token: turnstileToken
        })
      });
      
      const data = await res.json();
      if (res.ok) {
        // Role-based redirection
        if (data.user.role === 'admin' || data.user.role === 'super_admin') {
          window.location.href = '/role-select.html';
        } else {
          window.location.href = '/uc.html';
        }
      } else {
        alert(data.error.message || 'Login failed');
        // Reset Turnstile on failure
        if(turnstileWidgetId && window.turnstile) window.turnstile.reset(turnstileWidgetId); 
      }
    } catch (err) {
      console.error(err);
      alert('Network error');
    }
  });
}
