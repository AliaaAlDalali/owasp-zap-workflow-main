import { type FormEvent, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Card, EmptyState, ErrorState, Field, FormError, Icon, Skeleton, TextInput, useToast } from '../asaas-ui';
import { PageHead } from '../components/PageHead';
import { VerifiedPill } from '../components/StatusBadges';
import { t } from '../content';
import { post, useApi } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useOrgPath } from '../lib/org';
import type { Target } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';

export default function Sites() {
  usePageMeta(t('sites.title'));
  const orgPath = useOrgPath();
  const navigate = useNavigate();
  const notify = useToast();
  const { data, error, loading, reload } = useApi<Target[]>(orgPath && `${orgPath}/targets`);

  const [url, setUrl] = useState('');
  const [pending, setPending] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    if (!orgPath) return;
    setPending(true);
    setFormError(null);
    try {
      const target = await post<Target>(`${orgPath}/targets`, { url: url.trim() });
      notify(t('sites.added'));
      navigate(`/sites/${target.id}`);
    } catch (err) {
      setFormError(err);
      setPending(false);
    }
  };

  return (
    <div className="page">
      <PageHead title={t('sites.title')} lead={t('sites.lead')} />

      <Card title={t('sites.add')} icon="plus">
        <form className="form add-site" onSubmit={add}>
          <Field label={t('sites.urlLabel')} hint={t('sites.urlHint')}>
            {(id) => (
              <TextInput
                id={id}
                type="url"
                dir="ltr"
                inputMode="url"
                placeholder="https://"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                maxLength={2048}
              />
            )}
          </Field>
          <FormError error={formError} />
          <Button type="submit" variant="primary" icon="plus" loading={pending}>
            {t('sites.add')}
          </Button>
        </form>
      </Card>

      {loading && <Skeleton count={3} height={72} />}
      {error != null && !loading && <ErrorState error={error} onRetry={() => reload()} />}
      {data && !loading && data.length === 0 && (
        <Card>
          <EmptyState icon="globe" title={t('sites.emptyTitle')}>
            <p className="subtle">{t('sites.emptyBody')}</p>
          </EmptyState>
        </Card>
      )}
      {data && !loading && data.length > 0 && (
        <div className="list">
          {data.map((site) => (
            <Link key={site.id} to={`/sites/${site.id}`} className="row row--stack">
              <span className={`kind-icon ${site.verified ? 'kind-icon--in' : 'kind-icon--gold'}`} aria-hidden="true">
                <Icon name="globe" />
              </span>
              <span className="row__main">
                <span className="row__title" dir="ltr">
                  {site.url}
                </span>
                <span className="row__meta">{formatDateTime(site.verified_at ?? site.created_at)}</span>
              </span>
              <span className="row__amount">
                <VerifiedPill verified={site.verified} />
              </span>
              <Icon name="chevronLeft" className="row__chevron" />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
