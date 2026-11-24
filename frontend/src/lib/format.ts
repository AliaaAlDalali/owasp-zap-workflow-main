import { getLang } from './lang';

// The API stores times as UTC "YYYY-MM-DD HH:MM:SS".
function parse(value: string): Date {
  return new Date(value.includes('T') ? value : `${value.replace(' ', 'T')}Z`);
}

/** "22 نوف 2026، 14:05" in the visitor's time zone, Latin digits in both languages. */
export function formatDateTime(value: string | null): string {
  if (!value) return '';
  const locale = getLang() === 'en' ? 'en-GB' : 'ar-YE-u-nu-latn';
  return new Intl.DateTimeFormat(locale, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(parse(value));
}
