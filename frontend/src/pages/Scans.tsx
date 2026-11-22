import { Card, EmptyState, ErrorState, Skeleton } from '../asaas-ui';
import { PageHead } from '../components/PageHead';
import { ScanRow } from '../components/ScanRow';
import { t } from '../content';
import { useApi } from '../lib/api';
import { useOrgPath } from '../lib/org';
import type { Scan } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';

export default function Scans() {
  usePageMeta(t('scans.title'));
  const orgPath = useOrgPath();
  const { data, error, loading, reload } = useApi<Scan[]>(orgPath && `${orgPath}/scans?limit=200`);

  return (
    <div className="page">
      <PageHead title={t('scans.title')} lead={t('scans.lead')} />
      {loading && <Skeleton count={4} height={72} />}
      {error != null && !loading && <ErrorState error={error} onRetry={() => reload()} />}
      {data && !loading && data.length === 0 && (
        <Card>
          <EmptyState icon="shield" title={t('scans.emptyTitle')}>
            <p className="subtle">{t('scans.emptyBody')}</p>
          </EmptyState>
        </Card>
      )}
      {data && !loading && data.length > 0 && (
        <div className="list">
          {data.map((scan) => (
            <ScanRow key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}
