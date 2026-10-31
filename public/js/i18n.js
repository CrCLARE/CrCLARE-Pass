// ============================================================
// Nexus - Universal i18n Engine
// Priority: LocalStorage (Manual Switch) > Browser Language > English
// SECURITY: Uses textContent strictly to prevent XSS.
// ============================================================

export const SUPPORTED_LANGS = [
  { code: 'en', label: 'English' },
  { code: 'zh-CN', label: '简体中文' },
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'ja', label: '日本語' },
  { code: 'ru', label: 'Русский' },
  { code: 'de', label: 'Deutsch' },
  { code: 'fr', label: 'Français' },
  { code: 'es', label: 'Español' },
  { code: 'pt', label: 'Português' },
  { code: 'it', label: 'Italiano' },
  { code: 'ko', label: '한국어' },
  { code: 'pl', label: 'Polski' },
  { code: 'ar', label: 'العربية' }
];

let currentLocale = 'en';
let translations = {};

/**
 * Initialize the i18n engine and bind UI events.
 */
export async function initI18n() {
  const savedLang = localStorage.getItem('nexus_lang');
  const browserLang = navigator.language || 'en';
  
  // Priority logic: LocalStorage > Browser Language > Default 'en'
  const matched = SUPPORTED_LANGS.find(l => browserLang.toLowerCase().startsWith(l.code.toLowerCase().split('-')[0]));
  const targetLang = savedLang || (matched ? matched.code : 'en');
  
  await loadLocale(targetLang);
  
  // Wait for DOM to be ready before rendering
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      applyTranslations();
      setupSwitcherEvents();
    });
  } else {
    applyTranslations();
    setupSwitcherEvents();
  }
}

/**
 * Fetch the language dictionary from the server.
 * SECURITY: Ensure the path is strictly controlled to prevent LFI.
 */
export async function loadLocale(lang) {
  try {
    const res = await fetch(`/locales/${lang}.json`);
    if (!res.ok) throw new Error(`Failed to load locale: ${lang}`);
    
    translations = await res.json();
    currentLocale = lang;
    localStorage.setItem('nexus_lang', lang);
    
    // Handle Right-to-Left (RTL) layout for Arabic
    document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
  } catch (e) {
    console.error(`[i18n] Error loading ${lang}`, e);
  }
}

/**
 * Translate a specific key for JS scripts (e.g., alert messages).
 */
export function t(key) {
  return translations[key] || key;
}

/**
 * Scans the DOM and applies translations to all elements.
 * SECURITY: Uses textContent to prevent XSS injection from JSON.
 */
function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
  });
  
  renderDropdownItems();
}

/**
 * Binds event listeners to the language switcher button.
 */
function setupSwitcherEvents() {
  const btn = document.getElementById('lang-btn');
  const dropdown = document.getElementById('lang-dropdown');
  
  if (!btn || !dropdown) return;

  // Toggle dropdown on button click
  btn.addEventListener('click', (e) => {
    e.stopPropagation(); // Prevent event bubbling
    dropdown.classList.toggle('hidden');
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', (e) => {
    if (!dropdown.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
      dropdown.classList.add('hidden');
    }
  });
}

/**
 * Populates the dropdown menu with the supported languages.
 */
function renderDropdownItems() {
  const dropdown = document.getElementById('lang-dropdown');
  if (!dropdown) return;
  
  dropdown.innerHTML = ''; // Safely clear the container

  SUPPORTED_LANGS.forEach(lang => {
    const item = document.createElement('button');
    item.type = 'button';
    
    // Highlight the currently active language
    const isActive = lang.code === currentLocale;
    item.className = `w-full text-left px-5 py-2.5 text-[14px] transition-colors ${
      isActive 
        ? 'bg-[#3f3f46] text-gray-200 font-semibold' 
        : 'text-gray-300 hover:bg-[#3f3f46]/50'
    }`;
    
    item.textContent = lang.label;
    
    // Handle language switch
    item.onclick = async () => {
      if (lang.code === currentLocale) {
        dropdown.classList.add('hidden');
        return; 
      }
      dropdown.classList.add('hidden');
      await loadLocale(lang.code);
      applyTranslations();
    };
    
    dropdown.appendChild(item);
  });
}
