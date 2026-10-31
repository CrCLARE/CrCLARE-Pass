// ============================================================
// Nexus - i18n Engine
// SECURITY: Strictly uses textContent to inject translations.
// ============================================================

export const SUPPORTED_LANGS = [
  { code: 'en', label: 'lang.en' }, { code: 'zh-CN', label: 'lang.zh' },
  { code: 'zh-TW', label: 'lang.zht' }, { code: 'ja', label: 'lang.ja' },
  { code: 'ru', label: 'lang.ru' }, { code: 'de', label: 'lang.de' },
  { code: 'fr', label: 'lang.fr' }, { code: 'es', label: 'lang.es' },
  { code: 'pt', label: 'lang.pt' }, { code: 'it', label: 'lang.it' },
  { code: 'ko', label: 'lang.ko' }, { code: 'pl', label: 'lang.pl' },
  { code: 'ar', label: 'lang.ar' }
];

let currentLocale = 'en';
let translations = {};

export async function initI18n() {
  let savedLang = localStorage.getItem('nexus_lang');
  if (!savedLang) {
    const browserLang = navigator.language || navigator.userLanguage;
    const matched = SUPPORTED_LANGS.find(l => browserLang.toLowerCase().startsWith(l.code.toLowerCase().split('-')[0]));
    savedLang = matched ? matched.code : 'en';
  }
  await loadLocale(savedLang);
  translateDOM();
  renderLangSwitcher();
}

export async function loadLocale(lang) {
  try {
    const res = await fetch(`/locales/${lang}.json`);
    translations = await res.json();
    currentLocale = lang;
    localStorage.setItem('nexus_lang', lang);
    document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
  } catch (e) {
    console.error(`[i18n] Failed to load ${lang}`, e);
  }
}

export function t(key) { return translations[key] || key; }

export function translateDOM(root = document) {
  root.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.getAttribute('data-i18n')); });
  root.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder'))); });
}

function renderLangSwitcher() {
  const container = document.getElementById('lang-switcher');
  if (!container) return;
  container.textContent = ''; // Clear safely
  
  const currentLangObj = SUPPORTED_LANGS.find(l => l.code === currentLocale) || SUPPORTED_LANGS[0];
  
  const btn = document.createElement('button');
  btn.className = "text-gray-300 hover:text-white px-2 py-1 flex items-center gap-1 rounded transition-colors";
  btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 8l6 6"/><path d="M4 14h6"/><path d="M2 5h12"/><path d="M7 2h1"/><path d="M22 22l-5-10-5 10"/><path d="M14 18h6"/></svg> <span>${t(currentLangObj.label)}</span>`;
  
  const dropdown = document.createElement('div');
  dropdown.className = "absolute right-0 mt-2 w-48 bg-[#2d2d2d] border border-gray-700 rounded-xl shadow-2xl py-2 hidden z-50 max-h-80 overflow-y-auto";
  
  SUPPORTED_LANGS.forEach(lang => {
    const item = document.createElement('button');
    item.className = `w-full text-left px-4 py-2 text-sm transition-colors ${lang.code === currentLocale ? 'bg-blue-600/20 text-blue-400 font-medium' : 'text-gray-300 hover:bg-gray-700/50'}`;
    item.textContent = t(lang.label); // SECURITY: Safe injection
    item.onclick = async () => { dropdown.classList.add('hidden'); await loadLocale(lang.code); translateDOM(); renderLangSwitcher(); };
    dropdown.appendChild(item);
  });

  btn.onclick = (e) => { e.stopPropagation(); dropdown.classList.toggle('hidden'); };
  document.addEventListener('click', () => dropdown.classList.add('hidden'));

  container.appendChild(btn);
  container.appendChild(dropdown);
}
