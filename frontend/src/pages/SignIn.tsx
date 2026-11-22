import { type FormEvent, useState } from 'react';
import { Navigate, useSearchParams } from 'react-router-dom';
import {
  Button,
  Card,
  Field,
  FormError,
  Glass,
  PasswordInput,
  PasswordStrength,
  Segmented,
  Skeleton,
  Swash,
  TextInput,
} from '../asaas-ui';
import { Brand, LangSwitch, ThemeToggle } from '../components/Layout';
import { t } from '../content';
import { useAuth } from '../lib/auth';
import { safeNext } from '../lib/safeHref';
import { usePageMeta } from '../lib/usePageMeta';

type Mode = 'signIn' | 'register';

export default function SignIn() {
  usePageMeta(t('auth.submitSignIn'));
  const { user, signIn, register } = useAuth();
  const [params] = useSearchParams();
  const next = safeNext(params.get('next'));

  const [mode, setMode] = useState<Mode>(params.get('mode') === 'register' ? 'register' : 'signIn');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [organization, setOrganization] = useState('');
  const [website, setWebsite] = useState(''); // honeypot: people never see it, bots fill it
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  if (user) return <Navigate to={next} replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (website) return;
    setPending(true);
    setError(null);
    try {
      if (mode === 'signIn') await signIn(email.trim(), password);
      else await register({ email: email.trim(), password, name: name.trim(), organization_name: organization.trim() });
      // The redirect happens on the next render, once `user` is set.
    } catch (err) {
      setError(err);
      setPending(false);
    }
  };

  return (
    <div className="auth">
      <div className="container auth__top">
        <Glass thick pill className="auth__bar">
          <Brand />
          <div className="cluster auth__actions">
            <LangSwitch />
            <ThemeToggle />
          </div>
        </Glass>
      </div>

      <main className="container auth__main">
        <div className="auth__intro">
          <h1 className="display">
            <Swash>{t('auth.title')}</Swash>
          </h1>
          <p className="prose muted">{t('auth.lead')}</p>
        </div>

        <Card className="auth__card">
          {user === undefined ? (
            <Skeleton count={3} height={56} />
          ) : (
            <form className="form" onSubmit={submit}>
              <Segmented<Mode>
                label={t('auth.modeLabel')}
                value={mode}
                onChange={(value) => {
                  setMode(value);
                  setError(null);
                }}
                options={[
                  { value: 'signIn', label: t('auth.modeSignIn') },
                  { value: 'register', label: t('auth.modeRegister') },
                ]}
              />

              {mode === 'register' && (
                <Field label={t('auth.name')}>
                  {(id) => (
                    <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required maxLength={120} />
                  )}
                </Field>
              )}

              <Field label={t('auth.email')}>
                {(id) => (
                  <TextInput
                    id={id}
                    type="email"
                    dir="ltr"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                    maxLength={254}
                  />
                )}
              </Field>

              <Field label={t('auth.password')} hint={mode === 'register' ? t('auth.passwordHint') : undefined}>
                {(id) => (
                  <PasswordInput
                    id={id}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                    required
                    minLength={mode === 'register' ? 10 : 1}
                    maxLength={128}
                  />
                )}
              </Field>
              {mode === 'register' && <PasswordStrength password={password} />}

              {mode === 'register' && (
                <Field label={t('auth.organization')} hint={t('auth.organizationHint')}>
                  {(id) => (
                    <TextInput
                      id={id}
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      autoComplete="organization"
                      required
                      maxLength={120}
                    />
                  )}
                </Field>
              )}

              <input
                className="honeypot"
                type="text"
                name="website"
                tabIndex={-1}
                autoComplete="off"
                aria-hidden="true"
                value={website}
                onChange={(e) => setWebsite(e.target.value)}
              />

              <FormError error={error} />
              <Button type="submit" variant="primary" loading={pending}>
                {mode === 'signIn' ? t('auth.submitSignIn') : t('auth.submitRegister')}
              </Button>
            </form>
          )}
        </Card>
      </main>
    </div>
  );
}
