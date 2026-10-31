// ============================================================
// Nexus SDK (v1.2) - One-line SSO for Indie Blogs & Twikoo
// SECURITY: Uses window.postMessage with strict Origin validation 
// and CSRF state checking. Dynamically infers base URL.
// ============================================================

(function (global) {
  'use strict';

  // Default configuration
  let config = {
    nexusUrl: '', // SECURITY/DYNAMIC: Will be inferred from script src or data attribute
    clientId: '',
    redirectUri: window.location.origin
  };

  let authWindow = null;
  let currentToken = null;
  let currentUser = null;
  let currentState = null;

  try {
    const savedAuth = localStorage.getItem('nexus_sdk_auth');
    if (savedAuth) {
      const parsed = JSON.parse(savedAuth);
      currentToken = parsed.token;
      currentUser = parsed.user;
    }
  } catch (e) {
    console.warn('[NexusSDK] Failed to restore session from localStorage.');
  }

  /**
   * Initializes the SDK configuration from the script tag.
   * DYNAMIC: Automatically extracts the origin from the script src if not explicitly provided.
   */
  function init() {
    const scriptTag = document.currentScript || document.querySelector('script[src*="sdk/nexus.js"]') || document.querySelector('script[src*="sdk/index.js"]');
    
    if (scriptTag) {
      // 1. Try to get explicitly set URL from data attribute
      if (scriptTag.dataset.nexusUrl) {
        config.nexusUrl = scriptTag.dataset.nexusUrl;
      } 
      // 2. Fallback: Automatically extract Origin from the SDK's own URL
      else if (scriptTag.src) {
        try {
          const url = new URL(scriptTag.src);
          config.nexusUrl = url.origin;
        } catch (e) {
          console.error('[NexusSDK] Failed to parse script src URL.');
        }
      }

      // 3. Get Client ID and Redirect URI
      if (scriptTag.dataset.clientId) config.clientId = scriptTag.dataset.clientId;
      if (scriptTag.dataset.redirectUri) config.redirectUri = scriptTag.dataset.redirectUri;
    }

    // Validation
    if (!config.nexusUrl) {
      console.error('[NexusSDK] Cannot determine Nexus URL. Please provide data-nexus-url attribute or ensure script src is an absolute URL.');
    }
    if (!config.clientId) {
      console.error('[NexusSDK] Missing data-client-id attribute on the script tag.');
    }
  }

  function login() {
    if (!config.clientId || !config.nexusUrl) return;

    currentState = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);

    const authUrl = new URL(`${config.nexusUrl}/oauth-consent.html`);
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    authUrl.searchParams.set('state', currentState);
    
    const width = 500, height = 650;
    const left = (window.screen.width / 2) - (width / 2);
    const top = (window.screen.height / 2) - (height / 2);
    
    authWindow = window.open(
      authUrl.toString(), 
      'NexusSSO', 
      `width=${width},height=${height},top=${top},left=${left},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
    );

    if (!authWindow) alert('Popup blocked! Please allow popups.');
  }

  window.addEventListener('message', (event) => {
    // SECURITY: Ensure we are only accepting messages from the dynamically inferred Nexus URL
    if (!config.nexusUrl) return;
    
    try {
      if (event.origin !== new URL(config.nexusUrl).origin) return;
    } catch (e) {
      return;
    }

    const data = event.data;
    
    if (data && data.type === 'NEXUS_AUTH_SUCCESS') {
      if (data.state !== currentState) {
        console.error('[NexusSDK] State mismatch. Possible CSRF attack.');
        return;
      }

      if (authWindow) authWindow.close();
      
      currentToken = data.token;
      currentUser = data.user;
      
      try {
        localStorage.setItem('nexus_sdk_auth', JSON.stringify({
          token: currentToken,
          user: currentUser
        }));
      } catch (e) {
        console.warn('[NexusSDK] Could not save session to localStorage.');
      }

      document.dispatchEvent(new CustomEvent('nexus:login', { detail: currentUser }));
    }
  });

  function getUser() { return currentUser; }
  function getToken() { return currentToken; }

  function logout() {
    currentToken = null;
    currentUser = null;
    localStorage.removeItem('nexus_sdk_auth');
    document.dispatchEvent(new CustomEvent('nexus:logout'));
  }

  init();

  global.NexusSDK = {
    login,
    logout,
    getUser,
    getToken
  };

})(window);
