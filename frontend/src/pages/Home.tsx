import { Link } from 'react-router-dom';
import { Card, EmptyState, ErrorState, greeting, Skeleton, Stat } from '../asaas-ui';
import { PageHead } from '../components/PageHead';
import { ScanRow } from '../components/ScanRow';
import { ScoreRing } from '../components/ScoreRing';
import { ReleasePill } from '../components/StatusBadges';
import { t } from '../content';
import { useApi } from '../lib/api';
import { useAuth } from '../lib/auth';
import { formatDateTime } from '../lib/format';
import { useOrgPath } from '../lib/org';
import type { Scan, Target } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';

/** Latest completed scan per site, to count the sites whose release is blocked. */
function latestPerSite(scans: Scan[]): Scan[] {
  const seen = new Map<number, Scan>();
  for (const scan of scans) if (scan.status === 'completed' && !seen.has(scan.target_id)) seen.set(scan.target_id, scan);
  return [...seen.values()];
}

export default function Home() {
  usePageMeta(t('home.title'));
  const { user } = useAuth();
  const orgPath = useOrgPath();
  const targets = useApi<Target[]>(orgPath && `${orgPath}/targets`);
  const scans = useApi<Scan[]>(orgPath && `${orgPath}/scans?limit=200`);

  const head = <PageHead title={user ? greeting(user.name) : t('home.title')} lead={t('home.lead')} />;

  if (targets.loading || scans.loading) {
    return (
      <div className="page">
        {head}
        <Skeleton count={4} height={96} />
      </div>
    );
  }
  const error = targets.error ?? scans.error;
  if (error) {
    return (
      <div className="page">
        {head}
        <ErrorState
          error={error}
          onRetry={() => {
            targets.reload();
            scans.reload();
          }}
        />
      </div>
    );
  }

  const sites = targets.data ?? [];
  const allScans = scans.data ?? [];
  if (sites.length === 0) {
    return (
      <div className="page">
        {head}
        <Card>
          <EmptyState icon="globe" title={t('home.noSitesTitle')}>
            <p className="subtle">{t('home.noSitesBody')}</p>
            <Link to="/sites" className="btn btn--primary">
              {t('sites.add')}
            </Link>
          </EmptyState>
        </Card>
      </div>
    );
  }

  const verified = sites.filter((s) => s.verified).length;
  const active = allScans.filter((s) => s.status === 'queued' || s.status === 'running').length;
  const latest = latestPerSite(allScans);
  const blocked = latest.filter((s) => s.release_status === 'blocked').length;
  const lastCompleted = allScans.find((s) => s.status === 'completed');

  return (
    <div className="page">
      {head}
      <div className="grid grid--stats">
        <Stat label={t('home.sites')} icon="globe" amount={sites.length} unit={null} foot={t('home.verified', { n: verified })} />
        <Stat label={t('home.scans')} icon="shield" amount={allScans.length} unit={null} />
        <Stat label={t('home.active')} icon="clock" amount={active} unit={null} foot={t('home.activeFoot')} />
        <Stat
          label={t('home.blocked')}
          icon="alert"
          amount={blocked}
          unit={null}
          tone={blocked > 0 ? 'negative' : 'default'}
          foot={t('home.blockedFoot')}
        />
      </div>

      <div className="grid grid--main">
        <Card title={t('home.recent')} icon="list" actions={allScans.length > 0 && <Link to="/scans" className="btn btn--ghost btn--sm">{t('common.viewAll')}</Link>}>
          {allScans.length === 0 ? (
            <p className="subtle">{t('home.noScans')}</p>
          ) : (
            <div className="list">
              {allScans.slice(0, 6).map((scan) => (
                <ScanRow key={scan.id} scan={scan} />
              ))}
            </div>
          )}
        </Card>

        {lastCompleted && lastCompleted.score !== null && lastCompleted.release_status && (
          <Card title={t('home.latest')} icon="shield">
            <div className="latest">
              <ScoreRing score={lastCompleted.score} />
              <ReleasePill status={lastCompleted.release_status} />
              <p className="row__title" dir="ltr">{lastCompleted.target_url}</p>
              <p className="subtle">{formatDateTime(lastCompleted.finished_at ?? lastCompleted.created_at)}</p>
              <Link to={`/scans/${lastCompleted.id}`} className="btn btn--glass">
                {t('home.openScan')}
              </Link>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
