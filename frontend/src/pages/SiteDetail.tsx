import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Button, Card, ConfirmDialog, Icon, ErrorState, FormError, Skeleton, useToast } from '../asaas-ui';
import { CopyValue } from '../components/CopyValue';
import { PageHead } from '../components/PageHead';
import { ScanRow } from '../components/ScanRow';
import { VerifiedPill } from '../components/StatusBadges';
import { t } from '../content';
import { post, remove, useApi } from '../lib/api';
import { formatDateTime } from '../lib/format';
import { useOrg, useOrgPath } from '../lib/org';
import type { Scan, Target } from '../lib/types';
import { usePageMeta } from '../lib/usePageMeta';
import NotFound from './NotFound';

export default function SiteDetail() {
  const { id } = useParams();
  const siteId = Number(id);
  const orgPath = useOrgPath();
  const { org } = useOrg();
  const navigate = useNavigate();
  const notify = useToast();

  const valid = Number.isInteger(siteId) && siteId > 0;
  const target = useApi<Target>(orgPath && valid ? `${orgPath}/targets/${siteId}` : null);
  const scans = useApi<Scan[]>(orgPath && valid ? `${orgPath}/scans?target_id=${siteId}&limit=50` : null);
  usePageMeta(target.data?.host ?? t('sites.title'));

  const [busy, setBusy] = useState<'verify' | 'scan' | 'delete' | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (!valid) return <NotFound />;
  if (target.loading) {
    return (
      <div className="page">
        <Skeleton count={3} height={110} />
      </div>
    );
  }
  if (target.error || !target.data) {
    return (
      <div className="page">
        <ErrorState error={target.error} onRetry={() => target.reload()} />
      </div>
    );
  }

  const site = target.data;
  const base = `${orgPath}/targets/${site.id}`;
  const isOwner = org?.role === 'owner';

  const run = async (kind: 'verify' | 'scan') => {
    setBusy(kind);
    setActionError(null);
    try {
      if (kind === 'verify') {
        await post<Target>(`${base}/verify`);
        notify(t('site.verifiedToast'));
        target.reload(true);
      } else {
        const scan = await post<Scan>(`${base}/scans`);
        notify(t('site.scanQueued'));
        navigate(`/scans/${scan.id}`);
      }
    } catch (err) {
      setActionError(err);
    } finally {
      setBusy(null);
    }
  };

  const deleteSite = async () => {
    setBusy('delete');
    setActionError(null);
    try {
      await remove(base);
      notify(t('site.deleted'));
      navigate('/sites', { replace: true });
    } catch (err) {
      setActionError(err);
      setBusy(null);
    }
  };

  return (
    <div className="page">
      <Link to="/sites" className="back-link">
        <Icon name="chevronRight" />
        {t('common.back')}
      </Link>
      <PageHead
        title={site.host}
        titleDir="ltr"
        lead={<VerifiedPill verified={site.verified} />}
        actions={
          site.verified && (
            <Button variant="primary" icon="shield" loading={busy === 'scan'} disabled={busy !== null} onClick={() => run('scan')}>
              {t('site.startScan')}
            </Button>
          )
        }
      />
      {!confirmDelete && <FormError error={actionError} />}

      {!site.verified && site.verification && (
        <Card title={t('site.verifyTitle')} icon="shield">
          <div className="form">
            <p className="muted">{t('site.verifyLead')}</p>
            <div className="grid grid--halves">
              <div className="verify-option">
                <h3>{t('site.optionDns')}</h3>
                {site.verification.dns_record_name ? (
                  <>
                    <p className="subtle">{t('site.optionDnsBody')}</p>
                    <CopyValue label={t('site.recordName')} value={site.verification.dns_record_name} />
                    <CopyValue label={t('site.recordValue')} value={site.verification.dns_record_value} />
                  </>
                ) : (
                  <p className="subtle">{t('site.dnsNotForIp')}</p>
                )}
              </div>
              <div className="verify-option">
                <h3>{t('site.optionFile')}</h3>
                <p className="subtle">{t('site.optionFileBody')}</p>
                <CopyValue label={t('site.fileUrl')} value={site.verification.file_url} />
                <CopyValue label={t('site.fileContent')} value={site.verification.file_content} />
              </div>
            </div>
            <Button variant="primary" icon="check" loading={busy === 'verify'} disabled={busy !== null} onClick={() => run('verify')}>
              {t('site.verifyNow')}
            </Button>
          </div>
        </Card>
      )}

      {site.verified && site.verification_method && (
        <p className="subtle">
          {t('site.verifiedBy', { method: t(site.verification_method === 'dns' ? 'site.methodDns' : 'site.methodFile') })}
          {site.verified_at && ` · ${formatDateTime(site.verified_at)}`}
        </p>
      )}

      <Card title={t('site.history')} icon="list">
        {scans.loading && <Skeleton count={2} height={64} />}
        {scans.error != null && !scans.loading && <ErrorState error={scans.error} onRetry={() => scans.reload()} />}
        {scans.data && !scans.loading && scans.data.length === 0 && <p className="subtle">{t('site.noScans')}</p>}
        {scans.data && !scans.loading && scans.data.length > 0 && (
          <div className="list">
            {scans.data.map((scan) => (
              <ScanRow key={scan.id} scan={scan} showSite={false} />
            ))}
          </div>
        )}
      </Card>

      {isOwner && (
        <div className="danger-zone">
          <Button variant="danger" icon="trash" onClick={() => setConfirmDelete(true)}>
            {t('site.delete')}
          </Button>
        </div>
      )}

      {confirmDelete && (
        <ConfirmDialog
          title={t('site.delete')}
          onConfirm={deleteSite}
          onClose={() => {
            setConfirmDelete(false);
            setActionError(null);
          }}
          pending={busy === 'delete'}
          error={actionError}
        >
          {t('site.deleteBody', { host: site.host })}
        </ConfirmDialog>
      )}
    </div>
  );
}
