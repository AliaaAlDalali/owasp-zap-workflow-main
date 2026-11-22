import type { ReactNode } from 'react';
import { Button, ErrorState, Modal, Skeleton, useToast } from '../asaas-ui';
import { t } from '../content';
import { useApi } from '../lib/api';
import { useLang } from '../lib/lang';
import { safeHref } from '../lib/safeHref';
import type { Finding, FindingSummary } from '../lib/types';
import { RiskPill } from './StatusBadges';

/** ZAP writes references as one URL per line. */
function references(text: string): string[] {
  return text
    .split(/\s+/)
    .map((part) => part.trim())
    .filter((part) => /^https?:\/\//i.test(part));
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="finding__section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

/** Full detail of one finding: what it is, how to fix it, and where it was seen. */
export function FindingInspector({ orgPath, summary, onClose }: { orgPath: string; summary: FindingSummary; onClose: () => void }) {
  const { lang } = useLang();
  const notify = useToast();
  const { data, error, loading, reload } = useApi<Finding>(`${orgPath}/scans/${summary.scan_id}/findings/${summary.id}`);
  const title = lang === 'ar' && summary.name_ar ? summary.name_ar : summary.name;

  const copyCode = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      notify(t('common.copied'));
    } catch {
      notify(t('api.error'), 'error');
    }
  };

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="finding">
        <div className="cluster finding__meta">
          <RiskPill risk={summary.risk_code} />
          {summary.cwe_id && summary.cwe_id !== '0' && <span className="pill pill--neutral num">CWE-{summary.cwe_id}</span>}
          {data?.owasp && <span className="pill pill--neutral">{data.owasp}</span>}
          <span className="subtle">{t('scan.instances', { n: summary.instance_count })}</span>
        </div>

        {loading && <Skeleton count={3} height={72} />}
        {error != null && !loading && <ErrorState error={error} onRetry={() => reload()} />}

        {data && !loading && (
          <>
            {data.description && (
              <Section title={t('finding.description')}>
                <p className="prose finding__text" dir="auto">{data.description}</p>
              </Section>
            )}
            {data.solution && (
              <Section title={t('finding.solution')}>
                <p className="prose finding__text" dir="auto">{data.solution}</p>
              </Section>
            )}
            {data.remediation_code && (
              <Section title={data.remediation_title || t('finding.remediation')}>
                <div className="code-block">
                  <pre dir="ltr">
                    <code>{data.remediation_code}</code>
                  </pre>
                  <Button variant="glass" size="sm" icon="copy" onClick={() => copyCode(data.remediation_code)}>
                    {t('finding.copyCode')}
                  </Button>
                </div>
              </Section>
            )}
            {data.instances.length > 0 && (
              <Section title={t('finding.instances')}>
                <ul className="instances">
                  {data.instances.map((item, index) => (
                    <li key={index} className="instance">
                      <span className="instance__uri" dir="ltr">
                        <span className="pill pill--neutral">{item.method || 'GET'}</span> {item.uri}
                      </span>
                      {item.param && (
                        <span className="instance__detail">
                          {t('finding.param')}: <code dir="ltr">{item.param}</code>
                        </span>
                      )}
                      {item.attack && (
                        <span className="instance__detail">
                          {t('finding.attack')}: <code dir="ltr">{item.attack}</code>
                        </span>
                      )}
                      {item.evidence && (
                        <span className="instance__detail">
                          {t('finding.evidence')}: <code dir="ltr">{item.evidence}</code>
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </Section>
            )}
            {data.other_info && (
              <Section title={t('finding.otherInfo')}>
                <p className="prose finding__text" dir="auto">{data.other_info}</p>
              </Section>
            )}
            {references(data.reference).length > 0 && (
              <Section title={t('finding.references')}>
                <ul className="references">
                  {references(data.reference).map((url) => (
                    <li key={url}>
                      <a href={safeHref(url)} target="_blank" rel="noopener noreferrer" dir="ltr">
                        {url}
                      </a>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
