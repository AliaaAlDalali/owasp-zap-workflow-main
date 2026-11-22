import { getLang } from '../lib/lang';
import { ar, type TextKey } from './ar';
import { en } from './en';

export type { TextKey };

/** Fixed interface text in the current language. `{name}` placeholders are filled from params. */
export function t(key: TextKey, params?: Record<string, string | number>): string {
  let text: string = getLang() === 'en' ? en[key] : ar[key];
  if (params) {
    for (const [name, value] of Object.entries(params)) text = text.replaceAll(`{${name}}`, String(value));
  }
  return text;
}
