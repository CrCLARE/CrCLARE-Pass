// ============================================================
// Nexus SDK (v1.0) - One-line SSO for Indie Blogs & Twikoo
// SECURITY: Uses window.postMessage with strict Origin validation
// to prevent token interception by malicious third-party sites.
// ============================================================

(function (global) {
  'use strict';

  // Default configuration
  let config = {
    nexusUrl: 'https://pass.crclare.top', // Default Nexus Auth Server
    clientId: '',
    redirectUri: window.location.origin // Defaults to the current site
  };

  // Internal state
  let authWindow = null;
  let currentToken = null;
  let currentUser = null;

  // Load token from localStorage on init
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
   * Initializes the SDK configuration from the <script> tag data attributes.
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

    // Build the authorization URL
    const authUrl = new URL(`${config.nexusUrl}/oauth-consent.html`);
    authUrl.searchParams.set('client_id', config.clientId);
    authUrl.searchParams.set('redirect_uri', config.redirectUri);
    
    // Open a centered popup window
    const width = 500, height = 600;
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

  /**
   * Listens for the postMessage response from the Nexus auth window.
   */
  window.addEventListener('message', (event) => {
    // SECURITY: Strict Origin Validation. 
    // We only accept messages from the Nexus URL we explicitly configured.
    if (event.origin !== new URL(config.nexusUrl).origin) {
      return;
    }

    const data = event.data;
    
    if (data && data.type === 'NEXUS_AUTH_SUCCESS') {
      if (authWindow) authWindow.close();
      
      // Store the token and user info securely
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

      // Dispatch a custom event so the host site (e.g., blog) can react
      document.dispatchEvent(new CustomEvent('nexus:login', { detail: currentUser }));
    }
  });

  /**
   * Gets the currently logged-in user info.
   * @returns {Object|null} { id, nickname, email, avatar, isVerified }
   */
  function getUser() {
    return currentUser;
  }

  /**
   * Gets the raw JWT token for backend API calls (e.g., posting a Twikoo comment).
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

  // Initialization
  init();

  // Expose the public API to the global window object
  global.NexusSDK = {
    login,
    logout,
    getUser,
    getToken
  };

})(window);
