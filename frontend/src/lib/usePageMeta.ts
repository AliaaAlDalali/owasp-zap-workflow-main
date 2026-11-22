import { useEffect } from 'react';
import { t } from '../content';

/** Sets the tab title (and description) for a page and restores them when it leaves. */
export function usePageMeta(title?: string, description?: string) {
  useEffect(() => {
    const meta = document.querySelector('meta[name="description"]');
    const previousTitle = document.title;
    const previousDescription = meta?.getAttribute('content') ?? '';
    document.title = title ? `${title} | ${t('site.name')}` : `${t('site.name')} | ${t('site.tag')}`;
    meta?.setAttribute('content', description ?? t('site.description'));
    return () => {
      document.title = previousTitle;
      meta?.setAttribute('content', previousDescription);
    };
  }, [title, description]);
}
