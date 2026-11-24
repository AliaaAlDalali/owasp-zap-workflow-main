import { Link, NavLink, Outlet } from 'react-router-dom';
import { Button, Icon, type IconName, SiteHeader, TabBar, useTheme } from '../asaas-ui';
import { t, type TextKey } from '../content';
import { useAuth } from '../lib/auth';
import { useLang } from '../lib/lang';

const LINKS: { to: string; key: TextKey; icon: IconName; end?: boolean }[] = [
  { to: '/', key: 'nav.home', icon: 'dashboard', end: true },
  { to: '/sites', key: 'nav.sites', icon: 'globe' },
  { to: '/scans', key: 'nav.scans', icon: 'shield' },
  { to: '/settings', key: 'nav.settings', icon: 'users' },
];

export function Brand() {
  return (
    <Link to="/" className="brand">
      <span className="himaak-mark" aria-hidden="true">
        <Icon name="shield" />
      </span>
      <span>
        <span className="brand__name">{t('site.name')}</span>
        <span className="brand__tag hide-mobile">{t('site.tag')}</span>
      </span>
    </Link>
  );
}

export function LangSwitch() {
  const { lang, setLang } = useLang();
  return (
    <Button
      variant="ghost"
      size="sm"
      lang={lang === 'ar' ? 'en' : 'ar'}
      aria-label={t('action.langLabel')}
      onClick={() => setLang(lang === 'ar' ? 'en' : 'ar')}
    >
      {t('action.lang')}
    </Button>
  );
}

export function ThemeToggle() {
  const [theme, toggle] = useTheme();
  return <Button variant="ghost" icon={theme === 'dark' ? 'sun' : 'moon'} label={t('action.theme')} onClick={toggle} />;
}

/** The frame of every signed-in page: header, page area and the phone tab bar. */
export function Layout() {
  const { signOut } = useAuth();
  return (
    <>
      <SiteHeader
        brand={<Brand />}
        nav={LINKS.map((link) => (
          <NavLink key={link.to} to={link.to} end={link.end}>
            {t(link.key)}
          </NavLink>
        ))}
        actions={
          <>
            <LangSwitch />
            <ThemeToggle />
            <Button variant="ghost" icon="logout" label={t('action.signOut')} className="hide-mobile" onClick={signOut} />
          </>
        }
      />
      <main className="container">
        <Outlet />
      </main>
      <TabBar label={t('nav.label')}>
        {LINKS.map((link) => (
          <NavLink key={link.to} to={link.to} end={link.end}>
            <Icon name={link.icon} />
            {t(link.key)}
          </NavLink>
        ))}
      </TabBar>
    </>
  );
}
