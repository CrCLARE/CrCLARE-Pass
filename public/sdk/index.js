// ============================================================
// Nexus SDK (v1.1) - One-line SSO for Indie Blogs & Twikoo
// SECURITY: Uses window.postMessage with strict Origin validation 
// and CSRF state checking.
// ============================================================

(function (global) {
  'use strict';

  let config = {
    nexusUrl: 'https://pass.crclare.top', // Default URL, can be overridden
    clientId: '',
    redirectUri: window.location.origin
  };

  let authWindow = null;
  let currentToken = null;
  let currentUser = null;
  let currentState = null; // SECURITY: CSRF protection state

  // Restore session from localStorage if exists
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
   */
  function init() {
    const scriptTag = document.currentScript || document.querySelector('script[src*="nexus.js"]');
    if (scriptTag) {
      if (scriptTag.dataset.nexusUrl) config.nexusUrl = scriptTag.dataset.nexusUrl;
      if (scriptTag.dataset.clientId) config.clientId = scriptTag.dataset.clientId;
      if (scriptTag.dataset.redirectUri) config.redirectUri = scriptTag.dataset.redirectUri;
    }
    if (!config.clientId) {
      console.error('[NexusSDK] Missing data-client-id attribute on the script tag.');
    }
  }

  /**
   * Opens the Nexus login popup window.
   */
  function login() {
    if (!config.clientId) return;

    // SECURITY: Generate a random state to prevent CSRF attacks
    currentState = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);

    const authUrl = new URL(`${config.nexusUrl}/oauth-consent.html`);
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    authUrl.searchParams.set('state', currentState);
    
    // Open a centered popup window
    const width = 500, height = 650;
    const left = (window.screen.width / 2) - (width / 2);
    const top = (window.screen.height / 2) - (height / 2);
    
    authWindow = window.open(
      authUrl.toString(), 
      'NexusSSO', 
      `width=${width},height=${height},top=${top},left=${left},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`
    );

    if (!authWindow) {
      alert('Popup blocked! Please allow popups for this site to log in.');
    }
  }

  // Listen for the postMessage response from the consent window
  window.addEventListener('message', (event) => {
    // SECURITY: Strict Origin Validation. 
    // We only accept messages from the Nexus URL we configured.
    if (event.origin !== new URL(config.nexusUrl).origin) {
      return;
    }

    const data = event.data;
    
    if (data && data.type === 'NEXUS_AUTH_SUCCESS') {
      // SECURITY: Verify the state matches to prevent CSRF injection
      if (data.state !== currentState) {
        console.error('[NexusSDK] State mismatch. Possible CSRF attack.');
        return;
      }

      if (authWindow) authWindow.close();
      
      // Store token and user info
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

      // Dispatch custom event for the host site
      document.dispatchEvent(new CustomEvent('nexus:login', { detail: currentUser }));
    }
  });

  /**
   * Gets the currently logged-in user info.
   */
  function getUser() {
    return currentUser;
  }

  /**
   * Gets the raw JWT token for backend API calls.
   */
  function getToken() {
    return currentToken;
  }

  /**
   * Logs the user out and clears the local session.
   */
  function logout() {
    currentToken = null;
    currentUser = null;
    localStorage.removeItem('nexus_sdk_auth');
    document.dispatchEvent(new CustomEvent('nexus:logout'));
  }

  // Initialize and expose public API
  init();

  global.NexusSDK = {
    login,
    logout,
    getUser,
    getToken
  };

})(window);
