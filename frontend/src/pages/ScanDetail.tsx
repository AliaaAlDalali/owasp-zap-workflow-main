import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Button, Card, EmptyState, ErrorState, FormError, Icon, Skeleton, Stat, useToast } from '../asaas-ui';
import { FindingInspector } from '../components/FindingInspector';
import { PageHead } from '../components/PageHead';
import { ScoreRing } from '../components/ScoreRing';
import { ReleasePill, RiskPill, ScanStatusPill } from '../components/StatusBadges';
import { t } from '../content';
import { post, useApi } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useLang } from '../lib/lang';
import { useOrgPath } from '../lib/org';
import type { FindingSummary, RiskCode, Scan } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';
import NotFound from './NotFound';

const POLL_MS = 4000;
const RISKS: RiskCode[] = [3, 2, 1, 0];

export default function ScanDetail() {
  const { id } = useParams();
  const scanId = Number(id);
  const valid = Number.isInteger(scanId) && scanId > 0;
  const orgPath = useOrgPath();
  const scan = useApi<Scan>(orgPath && valid ? `${orgPath}/scans/${scanId}` : null);
  const status = scan.data?.status;
  const findings = useApi<FindingSummary[]>(orgPath && status === 'completed' ? `${orgPath}/scans/${scanId}/findings` : null);
  usePageMeta(t('scan.title'));

  // A queued or running scan is checked again every few seconds, quietly.
  const reloadScan = scan.reload;
  useEffect(() => {
    if (status !== 'queued' && status !== 'running') return;
    const timer = window.setInterval(() => reloadScan(true), POLL_MS);
    return () => window.clearInterval(timer);
  }, [status, reloadScan]);

  if (!valid) return <NotFound />;
  if (scan.loading) {
    return (
      <div className="page">
        <Skeleton count={3} height={120} />
      </div>
    );
  }
  if (scan.error || !scan.data || !orgPath) {
    return (
      <div className="page">
        <ErrorState error={scan.error} onRetry={() => scan.reload()} />
      </div>
    );
  }

  const data = scan.data;
  return (
    <div className="page">
      <Link to={`/sites/${data.target_id}`} className="back-link">
        <Icon name="chevronRight" />
        {t('scan.site')}
      </Link>
      <PageHead
        title={data.target_url}
        titleDir="ltr"
        lead={
          <span className="cluster">
            <ScanStatusPill status={data.status} />
            <span>
              {t('scan.requested')} {formatDateTime(data.created_at)}
            </span>
          </span>
        }
        actions={(data.status === 'completed' || data.status === 'failed') && <RescanButton orgPath={orgPath} scan={data} />}
      />

      {(data.status === 'queued' || data.status === 'running') && (
        <Card>
          <EmptyState icon="clock" title={t(data.status === 'queued' ? 'scan.queuedTitle' : 'scan.runningTitle')}>
            <p className="subtle">{t('scan.waitBody')}</p>
          </EmptyState>
        </Card>
      )}

      {data.status === 'failed' && (
        <Card>
          <EmptyState icon="alert" title={t('scan.failedTitle')}>
            {data.error && (
              <p className="subtle" dir="auto">
                {data.error}
              </p>
            )}
          </EmptyState>
        </Card>
      )}

      {data.status === 'completed' && <Report orgPath={orgPath} scan={data} findings={findings} />}
    </div>
  );
}

function RescanButton({ orgPath, scan }: { orgPath: string; scan: Scan }) {
  const navigate = useNavigate();
  const notify = useToast();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const rescan = async () => {
    setPending(true);
    setError(null);
    try {
      const next = await post<Scan>(`${orgPath}/targets/${scan.target_id}/scans`);
      notify(t('site.scanQueued'));
      navigate(`/scans/${next.id}`);
    } catch (err) {
      setError(err);
    } finally {
      setPending(false);
    }
  };
  return (
    <>
      <Button variant="glass" icon="refresh" loading={pending} onClick={rescan}>
        {t('scan.rescan')}
      </Button>
      <FormError error={error} />
    </>
  );
}

interface ReportProps {
  orgPath: string;
  scan: Scan;
  findings: ReturnType<typeof useApi<FindingSummary[]>>;
}

function Report({ orgPath, scan, findings }: ReportProps) {
  const { lang } = useLang();
  const [filter, setFilter] = useState<RiskCode | 'all'>('all');
  const [open, setOpen] = useState<FindingSummary | null>(null);
  const list = findings.data ?? [];
  const shown = filter === 'all' ? list : list.filter((f) => f.risk_code === filter);

  return (
    <>
      <div className="grid grid--main">
        <Card className="verdict">
          <ScoreRing score={scan.score ?? 0} />
          <div className="verdict__text">
            <span className="subtle">{t('scan.release')}</span>
            {scan.release_status && <ReleasePill status={scan.release_status} />}
            {scan.release_status && <p className="prose">{t(`release.${scan.release_status}Desc`)}</p>}
            {scan.zap_version && (
              <span className="subtle">
                {t('scan.engine')}: <span dir="ltr">OWASP ZAP {scan.zap_version}</span>
              </span>
            )}
            <Link to={`/scans/${scan.id}/compare`} className="btn btn--glass btn--sm">
              <Icon name="compare" />
              {t('scan.compare')}
            </Link>
          </div>
        </Card>
        <div className="grid grid--stats risk-stats">
          <Stat label={t('scan.high')} icon="alert" amount={scan.high_count} unit={null} tone={scan.high_count > 0 ? 'negative' : 'default'} />
          <Stat label={t('scan.medium')} icon="alert" amount={scan.medium_count} unit={null} />
          <Stat label={t('scan.low')} icon="eye" amount={scan.low_count} unit={null} />
          <Stat label={t('scan.info')} icon="file" amount={scan.info_count} unit={null} />
        </div>
      </div>

      <Card title={t('scan.findings')} icon="list">
        {findings.loading && <Skeleton count={3} height={64} />}
        {findings.error != null && !findings.loading && <ErrorState error={findings.error} onRetry={() => findings.reload()} />}
        {!findings.loading && !findings.error && list.length === 0 && <p className="subtle">{t('scan.clean')}</p>}
        {!findings.loading && list.length > 0 && (
          <>
            <div className="chips" role="group" aria-label={t('scan.filterLabel')}>
              <button type="button" className="chip" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>
                {t('scan.all')} <span className="num">{list.length}</span>
              </button>
              {RISKS.map((risk) => {
                const count = list.filter((f) => f.risk_code === risk).length;
                return (
                  <button key={risk} type="button" className="chip" aria-pressed={filter === risk} onClick={() => setFilter(risk)}>
                    {t(`risk.${risk}`)} <span className="num">{count}</span>
                  </button>
                );
              })}
            </div>
            {shown.length === 0 ? (
              <p className="subtle">{t('scan.noFindings')}</p>
            ) : (
              <div className="list">
                {shown.map((finding) => (
                  <button key={finding.id} type="button" className="row row--stack finding-row" onClick={() => setOpen(finding)}>
                    <span className="row__main">
                      <span className="row__title">{lang === 'ar' && finding.name_ar ? finding.name_ar : finding.name}</span>
                      <span className="row__meta">{t('scan.instances', { n: finding.instance_count })}</span>
                    </span>
                    <span className="row__amount">
                      <RiskPill risk={finding.risk_code} />
                    </span>
                    <Icon name="chevronLeft" className="row__chevron" />
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </Card>

      {open && <FindingInspector orgPath={orgPath} summary={open} onClose={() => setOpen(null)} />}
    </>
  );
}
