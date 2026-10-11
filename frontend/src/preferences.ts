export function savedLanguage(): string {
  try {
    const value = localStorage.getItem('firewall-language');
    if (value === 'ru' || value === 'en') return value;
  } catch { /* Storage can be blocked by the browser. */ }
  return 'ru';
}

export function saveLanguage(value: string) {
  try { localStorage.setItem('firewall-language', value); }
  catch { /* The selected language still works for this session. */ }
}
