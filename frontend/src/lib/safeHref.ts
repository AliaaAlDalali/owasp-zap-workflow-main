/**
 * Makes a URL that arrived as data safe to use as an href: only http, https,
 * mailto, tel and same-site paths pass; anything else becomes '#'.
 */
export function safeHref(value: string): string {
  const raw = value.trim();
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f]/.test(raw)) return '#';
  try {
    const url = new URL(raw, window.location.origin);
    if (url.protocol === 'mailto:' || url.protocol === 'tel:') return raw;
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return '#';
    if (url.origin === window.location.origin) return url.pathname + url.search + url.hash;
    return raw.startsWith('/') ? '#' : url.href; // a "path" that leaves the site is refused
  } catch {
    return '#';
  }
}

/** A same-site path for `?next=`, or the fallback. */
export function safeNext(value: string | null, fallback = '/'): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return fallback;
  const href = safeHref(value);
  return href.startsWith('/') ? href : fallback;
}
