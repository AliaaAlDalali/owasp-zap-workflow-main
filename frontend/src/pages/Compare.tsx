import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Card, ErrorState, Icon, type IconName, Skeleton, Stat } from '../asaas-ui';
import { FindingInspector } from '../components/FindingInspector';
import { PageHead } from '../components/PageHead';
import { RiskPill } from '../components/StatusBadges';
import { t, type TextKey } from '../content';
import { useApi } from '../lib/api';
import { useLang } from '../lib/lang';
import { useOrgPath } from '../lib/org';
import type { Comparison, FindingSummary } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';
import NotFound from './NotFound';

const GROUPS: { key: 'new' | 'fixed' | 'persisting'; title: TextKey; empty: TextKey; icon: IconName }[] = [
  { key: 'new', title: 'compare.new', empty: 'compare.noneNew', icon: 'alert' },
  { key: 'fixed', title: 'compare.fixed', empty: 'compare.noneFixed', icon: 'checkCircle' },
  { key: 'persisting', title: 'compare.persisting', empty: 'compare.nonePersisting', icon: 'clock' },
];

export default function Compare() {
  usePageMeta(t('compare.title'));
  const { id } = useParams();
  const scanId = Number(id);
  const valid = Number.isInteger(scanId) && scanId > 0;
  const orgPath = useOrgPath();
  const { lang } = useLang();
  const { data, error, loading, reload } = useApi<Comparison>(orgPath && valid ? `${orgPath}/scans/${scanId}/compare` : null);
  const [open, setOpen] = useState<FindingSummary | null>(null);

  if (!valid) return <NotFound />;

  return (
    <div className="page">
      <Link to={`/scans/${scanId}`} className="back-link">
        <Icon name="chevronRight" />
        {t('compare.backToScan')}
      </Link>
      <PageHead title={t('compare.title')} lead={t('compare.lead')} />
      {loading && <Skeleton count={3} height={96} />}
      {error != null && !loading && <ErrorState error={error} onRetry={() => reload()} />}
      {data && !loading && (
        <>
          {data.base_scan_id === null && <p className="muted">{t('compare.firstScan')}</p>}
          <div className="grid grid--stats">
            {GROUPS.map((group) => (
              <Stat
                key={group.key}
                label={t(group.title)}
                icon={group.icon}
                amount={data[group.key].length}
                unit={null}
                tone={group.key === 'new' && data.new.length > 0 ? 'negative' : 'default'}
              />
            ))}
          </div>
          {GROUPS.map((group) => (
            <Card key={group.key} title={t(group.title)} icon={group.icon}>
              {data[group.key].length === 0 ? (
                <p className="subtle">{t(group.empty)}</p>
              ) : (
                <div className="list">
                  {data[group.key].map((finding) => (
                    <button key={finding.id} type="button" className="row row--stack finding-row" onClick={() => setOpen(finding)}>
                      <span className="row__main">
                        <span className="row__title">{lang === 'ar' && finding.name_ar ? finding.name_ar : finding.name}</span>
                        <span className="row__meta">{t('scan.instances', { n: finding.instance_count })}</span>
                      </span>
                      <span className="row__amount">
                        <RiskPill risk={finding.risk_code} />
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </>
      )}
      {open && orgPath && <FindingInspector orgPath={orgPath} summary={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
