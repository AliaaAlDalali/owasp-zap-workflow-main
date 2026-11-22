import { createContext, type ReactNode, useCallback, useContext, useState } from 'react';

export type Lang = 'ar' | 'en';
const KEY = 'asaas-lang';

// theme-init.js has already set <html lang> before the first paint.
let current: Lang = document.documentElement.lang === 'en' ? 'en' : 'ar';

/** For code outside React (the API client, t()). */
export function getLang(): Lang {
  return current;
}

function apply(lang: Lang) {
  current = lang;
  const root = document.documentElement;
  root.lang = lang;
  root.dir = lang === 'en' ? 'ltr' : 'rtl';
  try {
    localStorage.setItem(KEY, lang);
  } catch {
    /* storage unavailable: the choice lasts for this visit */
  }
}

const LangContext = createContext<{ lang: Lang; setLang: (lang: Lang) => void }>({
  lang: current,
  setLang: () => {},
});

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setState] = useState<Lang>(current);
  const setLang = useCallback((next: Lang) => {
    apply(next); // before re-render, so the kit's words (read from <html lang>) follow at once
    setState(next);
  }, []);
  return <LangContext.Provider value={{ lang, setLang }}>{children}</LangContext.Provider>;
}

export function useLang() {
  return useContext(LangContext);
}
