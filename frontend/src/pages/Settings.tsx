import { type FormEvent, useState } from 'react';
import { Avatar, Button, Card, ErrorState, Field, FormError, Select, Skeleton, TextInput, useToast } from '../asaas-ui';
import { PageHead } from '../components/PageHead';
import { t } from '../content';
import { post, useApi } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useOrg, useOrgPath } from '../lib/org';
import type { Member, Organization } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';

export default function Settings() {
  usePageMeta(t('settings.title'));
  const { user, signOut } = useAuth();
  const { org, orgs, setOrgId } = useOrg();

  return (
    <div className="page">
      <PageHead title={t('settings.title')} />
      <div className="grid grid--halves">
        <Card title={t('settings.organization')} icon="briefcase">
          <div className="form">
            {orgs.length > 1 && org && (
              <Field label={t('settings.currentOrg')}>
                {(id) => (
                  <Select id={id} value={org.id} onChange={(e) => setOrgId(Number(e.target.value))}>
                    {orgs.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.name}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            )}
            {orgs.length <= 1 && org && <p className="row__title">{org.name}</p>}
            <NewOrganization />
          </div>
        </Card>

        <Card title={t('settings.account')} icon="users">
          <div className="form">
            {user && (
              <div className="row">
                <Avatar name={user.name} />
                <span className="row__main">
                  <span className="row__title">{user.name}</span>
                  <span className="row__meta" dir="ltr">
                    {user.email}
                  </span>
                </span>
              </div>
            )}
            <Button variant="glass" icon="logout" onClick={signOut}>
              {t('action.signOut')}
            </Button>
          </div>
        </Card>
      </div>

      {org && <Members key={org.id} org={org} />}
    </div>
  );
}

function Members({ org }: { org: Organization }) {
  const orgPath = useOrgPath();
  const notify = useToast();
  const { data, error, loading, reload } = useApi<Member[]>(orgPath && `${orgPath}/members`);
  const [email, setEmail] = useState('');
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);
  const isOwner = org.role === 'owner';

  const add = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setFormError(null);
    try {
      await post<Member>(`${orgPath}/members`, { email: email.trim() });
      notify(t('settings.memberAdded'));
      setEmail('');
      reload(true);
    } catch (err) {
      setFormError(err);
    } finally {
      setPending(false);
    }
  };

  return (
    <Card title={t('settings.members')} icon="users">
      <div className="form">
        {loading && <Skeleton count={2} height={60} />}
        {error != null && !loading && <ErrorState error={error} onRetry={() => reload()} />}
        {data && !loading && (
          <div className="list">
            {data.map((member) => (
              <div key={member.user_id} className="row">
                <Avatar name={member.name} />
                <span className="row__main">
                  <span className="row__title">{member.name}</span>
                  <span className="row__meta" dir="ltr">
                    {member.email}
                  </span>
                </span>
                <span className={`pill ${member.role === 'owner' ? 'pill--partial' : 'pill--neutral'}`}>
                  {t(member.role === 'owner' ? 'settings.role.owner' : 'settings.role.member')}
                </span>
              </div>
            ))}
          </div>
        )}
        {isOwner ? (
          <form className="form" onSubmit={add}>
            <Field label={t('settings.memberEmail')} hint={t('settings.memberHint')}>
              {(id) => (
                <TextInput
                  id={id}
                  type="email"
                  dir="ltr"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="off"
                  required
                  maxLength={254}
                />
              )}
            </Field>
            <FormError error={formError} />
            <Button type="submit" variant="primary" icon="plus" loading={pending}>
              {t('settings.addMember')}
            </Button>
          </form>
        ) : (
          <p className="subtle">{t('settings.ownerOnly')}</p>
        )}
      </div>
    </Card>
  );
}

function NewOrganization() {
  const { reload, setOrgId } = useOrg();
  const notify = useToast();
  const [name, setName] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const created = await post<Organization>('/organizations', { name: name.trim() });
      notify(t('settings.orgCreated'));
      setName('');
      setOrgId(created.id);
      reload();
    } catch (err) {
      setError(err);
    } finally {
      setPending(false);
    }
  };

  return (
    <form className="form" onSubmit={create}>
      <Field label={t('settings.newOrgName')}>
        {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} />}
      </Field>
      <FormError error={error} />
      <Button type="submit" variant="glass" icon="plus" loading={pending}>
        {t('settings.newOrg')}
      </Button>
    </form>
  );
}
