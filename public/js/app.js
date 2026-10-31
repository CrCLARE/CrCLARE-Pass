// ============================================================
// Nexus - Dynamic Frontend Application Logic
// SECURITY: Uses textContent strictly for DOM injection to prevent XSS.
// Handles dynamic configuration, OAuth rendering, login, and registration flows.
// ============================================================

// Supported OAuth providers mapping. 
// The frontend will only render the ones returned by the backend config.
const OAUTH_PROVIDERS = {
  github: {
    name: 'GitHub',
    icon: `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>`
  }
  // Future providers (Google, Microsoft, QQ, etc.) will be mapped here.
};

// Global state to store backend configuration
window.NEXUS_CONFIG = window.NEXUS_CONFIG || {};

// ============================================================
// Core Initialization
// ============================================================

/**
 * Initializes the application by fetching dynamic configuration from the backend.
 * Updates site branding, OAuth buttons, and footer dynamically.
 */
export async function initApp() {
  try {
    const res = await fetch('/api/config/public');
    const config = await res.json();

    // Save configuration globally for other functions to access
    window.NEXUS_CONFIG = config;

    // 1. Update Site Name (Fallback to default HTML if not set)
    const siteNameEl = document.getElementById('site-name');
    if (siteNameEl && config.siteName) {
      siteNameEl.textContent = config.siteName;
      document.title = document.title.replace('Nexus', config.siteName);
    }

    // 2. Update Logo (Supports URL or Base64)
    const logoImg = document.getElementById('dynamic-logo-img');
    const defaultLogo = document.getElementById('default-logo');
    const logoContainer = document.getElementById('site-logo-container');
    
    if (config.siteLogo && logoImg) {
      // SECURITY: Ensure it's a valid image URL or safe data URI
      if (config.siteLogo.startsWith('data:image/') || config.siteLogo.startsWith('http')) {
        logoImg.src = config.siteLogo;
        logoImg.classList.remove('hidden');
        if (defaultLogo) defaultLogo.classList.add('hidden');
        // Remove default background color if custom logo is used
        if (logoContainer) logoContainer.classList.remove('bg-[#93c5fd]');
      }
    }

    // 3. Dynamically Render OAuth Buttons
    const oauthContainer = document.getElementById('oauth-container');
    const oauthSection = document.getElementById('oauth-section');
    
    if (config.enabledOAuths && config.enabledOAuths.length > 0 && oauthContainer && oauthSection) {
      oauthSection.classList.remove('hidden');
      oauthContainer.innerHTML = ''; // Clear skeleton

      config.enabledOAuths.forEach(providerKey => {
        const provider = OAUTH_PROVIDERS[providerKey];
        if (!provider) return; // Skip if provider is not supported in frontend mapping

        const btn = document.createElement('a');
        btn.href = `/api/oauth/${providerKey}`;
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
    // Fail-safe: The HTML defaults will remain visible if the API fails.
  }
}

// ============================================================
// Helper: Dynamic CAPTCHA SDK Loader
// ============================================================

/**
 * Dynamically loads the required CAPTCHA SDK based on backend configuration.
 */
async function loadCaptchaSDK(provider) {
  return new Promise((resolve) => {
    if (provider === 'turnstile') {
      if (window.turnstile) return resolve();
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true;
      script.onload = resolve;
      document.head.appendChild(script);
    } else if (provider === 'recaptcha') {
      if (window.grecaptcha) return resolve();
      const script = document.createElement('script');
      script.src = 'https://www.google.com/recaptcha/api.js?render=explicit';
      script.async = true;
      script.onload = resolve;
      document.head.appendChild(script);
    } else if (provider === 'geetest') {
      if (window.initGeetest4) return resolve();
      const script = document.createElement('script');
      script.src = 'https://static.geetest.com/v4/gt4.js';
      script.async = true;
      script.onload = resolve;
      document.head.appendChild(script);
    } else {
      resolve(); // 'none' or unhandled provider
    }
  });
}

// ============================================================
// Login Flow
// ============================================================

/**
 * Sets up the two-step login flow, view transitions, and form submissions.
 */
export function setupLoginFlow() {
  const stepEmail = document.getElementById('step-email');
  const stepPassword = document.getElementById('step-password');
  const emailForm = document.getElementById('emailForm');
  const passwordForm = document.getElementById('passwordForm');
  const backBtn = document.getElementById('backToEmail');
  const displayEmail = document.getElementById('display-email');
  const captchaContainer = document.getElementById('turnstile-container');
  
  // Exit if not on the login page
  if (!emailForm || !passwordForm) return;

  let currentEmail = '';
  let captchaWidgetId = null;

  // Step 1: Proceed to password view
  emailForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    currentEmail = document.getElementById('email').value.trim();
    if (!currentEmail) return;

    // Update UI
    displayEmail.textContent = currentEmail;
    stepEmail.classList.add('step-hidden');
    stepPassword.classList.remove('step-hidden');
    
    // Focus the password input
    setTimeout(() => document.getElementById('password').focus(), 100);

    // Handle CAPTCHA rendering dynamically
    const config = window.NEXUS_CONFIG;
    if (config.captchaProvider && config.captchaProvider !== 'none' && config.captchaSiteKey) {
      captchaContainer.classList.remove('hidden');
      await loadCaptchaSDK(config.captchaProvider);

      // Initialize specific CAPTCHA
      if (config.captchaProvider === 'turnstile' && window.turnstile && !captchaWidgetId) {
        captchaWidgetId = window.turnstile.render('#turnstile-container', {
          sitekey: config.captchaSiteKey,
          theme: 'dark',
        });
      } 
      else if (config.captchaProvider === 'recaptcha' && window.grecaptcha && !captchaWidgetId) {
        captchaWidgetId = window.grecaptcha.render('turnstile-container', {
          sitekey: config.captchaSiteKey,
          theme: 'dark'
        });
      }
      else if (config.captchaProvider === 'geetest' && window.initGeetest4 && !captchaWidgetId) {
        window.initGeetest4({ captchaId: config.captchaSiteKey, product: "bind" }, function (captcha) {
          captcha.appendTo("#turnstile-container");
          window.geetestInstance = captcha;
          captchaWidgetId = 'geetest_rendered';
        });
      }
    } else {
      captchaContainer.classList.add('hidden');
    }
  });

  // Back button logic
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      stepPassword.classList.add('step-hidden');
      stepEmail.classList.remove('step-hidden');
      document.getElementById('password').value = '';
      
      // Reset CAPTCHA if it was rendered
      const config = window.NEXUS_CONFIG;
      if (captchaWidgetId) {
        if (config.captchaProvider === 'turnstile' && window.turnstile) window.turnstile.reset(captchaWidgetId);
        if (config.captchaProvider === 'recaptcha' && window.grecaptcha) window.grecaptcha.reset(captchaWidgetId);
        if (config.captchaProvider === 'geetest' && window.geetestInstance) window.geetestInstance.reset();
      }
    });
  }

  // Step 2: Submit password for authentication
  passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('password').value;
    const config = window.NEXUS_CONFIG;
    
    let captchaToken = '';

    // SECURITY: Only extract token if CAPTCHA is required
    if (config.captchaProvider && config.captchaProvider !== 'none') {
      if (config.captchaProvider === 'turnstile' && window.turnstile) {
        captchaToken = window.turnstile.getResponse(captchaWidgetId);
      } 
      else if (config.captchaProvider === 'recaptcha' && window.grecaptcha) {
        captchaToken = window.grecaptcha.getResponse(captchaWidgetId);
      }
      else if (config.captchaProvider === 'geetest' && window.geetestInstance) {
        const result = window.geetestInstance.getValidate();
        if (result) captchaToken = JSON.stringify(result);
      }

      if (!captchaToken) {
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
          captcha_token: captchaToken
        })
      });
      
      const data = await res.json();
      if (res.ok) {
        // Role-based redirection
        if (data.user && (data.user.role === 'admin' || data.user.role === 'super_admin')) {
          window.location.href = '/role-select.html';
        } else {
          window.location.href = '/uc.html';
        }
      } else {
        alert(data.error?.message || 'Login failed'); 
        // Reset CAPTCHA on failure
        if (captchaWidgetId) {
          if (config.captchaProvider === 'turnstile' && window.turnstile) window.turnstile.reset(captchaWidgetId);
          if (config.captchaProvider === 'recaptcha' && window.grecaptcha) window.grecaptcha.reset(captchaWidgetId);
        }
      }
    } catch (err) {
      console.error('[Login Error]', err);
      alert('Network error, please try again.');
    }
  });
}

// ============================================================
// Registration Flow
// ============================================================

/**
 * Sets up the registration flow, including dynamic password policy checks,
 * CAPTCHA loading, and strict terms agreement validation.
 */
export function setupRegisterFlow() {
  const registerForm = document.getElementById('registerForm');
  if (!registerForm) return; // Exit if not on the register page

  const passwordInput = document.getElementById('password');
  const confirmPasswordInput = document.getElementById('confirmPassword');
  const togglePwdBtn = document.getElementById('togglePwdBtn');
  const strengthBar = document.getElementById('strengthBar');
  const pwdHint = document.getElementById('pwdHint');
  const termsCheckbox = document.getElementById('termsCheckbox');
  const captchaContainer = document.getElementById('turnstile-container');

  let captchaWidgetId = null;

  // 1. Password Visibility Toggle
  if (togglePwdBtn) {
    togglePwdBtn.addEventListener('click', () => {
      const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
      passwordInput.setAttribute('type', type);
      if (confirmPasswordInput) confirmPasswordInput.setAttribute('type', type); 
    });
  }

  // 2. Dynamic Password Strength Evaluation
  if (passwordInput) {
    passwordInput.addEventListener('input', () => {
      const val = passwordInput.value;
      const policy = window.NEXUS_CONFIG.passwordPolicy || { 
        minLength: 8, requireUppercase: false, requireNumbers: false, requireSpecial: false 
      };

      let score = 0;
      
      // Length check
      if (val.length >= policy.minLength) score++;
      if (val.length >= policy.minLength + 4) score++; // Bonus for extra length
      
      // Character checks
      if (policy.requireUppercase && /[A-Z]/.test(val)) score++;
      if (policy.requireNumbers && /[0-9]/.test(val)) score++;
      if (policy.requireSpecial && /[^A-Za-z0-9]/.test(val)) score++;

      // Update Strength Bar UI
      let width = 0;
      let color = '#27272a';
      
      if (val.length > 0) {
        if (score <= 1) { width = 33; color = '#ef4444'; } // Red (Weak)
        else if (score <= 3) { width = 66; color = '#f59e0b'; } // Yellow (Medium)
        else { width = 100; color = '#10b981'; } // Green (Strong)
      }
      
      strengthBar.style.width = `${width}%`;
      strengthBar.style.backgroundColor = color;

      // Show policy hint text if not meeting requirements
      if (val.length > 0 && score <= 1 && pwdHint) {
        pwdHint.classList.remove('hidden');
        pwdHint.textContent = `Requires min ${policy.minLength} chars${policy.requireUppercase ? ', 1 uppercase' : ''}${policy.requireNumbers ? ', 1 number' : ''}${policy.requireSpecial ? ', 1 special char' : ''}.`;
      } else if (pwdHint) {
        pwdHint.classList.add('hidden');
      }
    });
  }

  // 3. Handle Form Submission
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('email').value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    const config = window.NEXUS_CONFIG;

    // SECURITY: Client-side checks (Backend will strictly re-validate)
    if (password !== confirmPassword) {
      return alert("Passwords do not match.");
    }

    // SECURITY: Mandatory GDPR Terms Agreement Check
    if (!termsCheckbox.checked) {
      return alert("You must agree to the Terms of Service and Privacy Policy.");
    }

    // SECURITY: Extract CAPTCHA token if required
    let captchaToken = '';
    if (config.captchaProvider && config.captchaProvider !== 'none' && config.captchaSiteKey) {
      if (!captchaWidgetId) {
         return alert("Please wait for the verification module to load.");
      }
      
      if (config.captchaProvider === 'turnstile' && window.turnstile) {
        captchaToken = window.turnstile.getResponse(captchaWidgetId);
      } 
      else if (config.captchaProvider === 'recaptcha' && window.grecaptcha) {
        captchaToken = window.grecaptcha.getResponse(captchaWidgetId);
      }
      else if (config.captchaProvider === 'geetest' && window.geetestInstance) {
        const result = window.geetestInstance.getValidate();
        if (result) captchaToken = JSON.stringify(result);
      }

      if (!captchaToken) {
        return alert("Please complete the human verification.");
      }
    }

    // Submit data to backend
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          password: password,
          agreed_to_terms: termsCheckbox.checked,
          terms_version: config.termsVersion || 'v1.0', // Sent to backend for version validation
          captcha_token: captchaToken
        })
      });

      const data = await res.json();

      if (res.ok) {
        // Registration successful, backend sets HttpOnly cookie.
        // Redirect straight to User Center.
        window.location.href = '/uc.html';
      } else {
        alert(data.error?.message || 'Registration failed.');
        // Reset CAPTCHA on failure
        if (captchaWidgetId) {
          if (config.captchaProvider === 'turnstile' && window.turnstile) window.turnstile.reset(captchaWidgetId);
          if (config.captchaProvider === 'recaptcha' && window.grecaptcha) window.grecaptcha.reset(captchaWidgetId);
        }
      }
    } catch (err) {
      console.error('[Register Error]', err);
      alert('Network error, please try again.');
    }
  });

  // 4. Initialize CAPTCHA on page load for register form
  const config = window.NEXUS_CONFIG;
  if (config.captchaProvider && config.captchaProvider !== 'none' && config.captchaSiteKey) {
    captchaContainer.classList.remove('hidden');
    loadCaptchaSDK(config.captchaProvider).then(() => {
      if (config.captchaProvider === 'turnstile' && window.turnstile) {
        captchaWidgetId = window.turnstile.render('#turnstile-container', {
          sitekey: config.captchaSiteKey,
          theme: 'dark',
        });
      } 
      else if (config.captchaProvider === 'recaptcha' && window.grecaptcha) {
        captchaWidgetId = window.grecaptcha.render('turnstile-container', {
          sitekey: config.captchaSiteKey,
          theme: 'dark'
        });
      }
      else if (config.captchaProvider === 'geetest' && window.initGeetest4) {
        window.initGeetest4({ captchaId: config.captchaSiteKey, product: "bind" }, function (captcha) {
          captcha.appendTo("#turnstile-container");
          window.geetestInstance = captcha;
          captchaWidgetId = 'geetest_rendered';
        });
      }
    });
  }
}
