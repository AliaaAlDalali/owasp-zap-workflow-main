import { Link } from 'react-router-dom';
import { Icon } from '../asaas-ui';
import { t } from '../content';
import { formatDateTime } from '../lib/format';
import type { Scan } from '../lib/types';
import { ReleasePill, ScanStatusPill } from './StatusBadges';

/** One scan in a list: site, time, and either its release decision or its status. */
export function ScanRow({ scan, showSite = true }: { scan: Scan; showSite?: boolean }) {
  const done = scan.status === 'completed' && scan.release_status;
  return (
    <Link to={`/scans/${scan.id}`} className="row row--stack">
      <span className="kind-icon kind-icon--gold" aria-hidden="true">
        <Icon name="shield" />
      </span>
      <span className="row__main">
        <span className="row__title" dir="ltr">
          {showSite ? scan.target_url : `#${scan.id}`}
        </span>
        <span className="row__meta">{formatDateTime(scan.created_at)}</span>
      </span>
      <span className="row__amount cluster scan-row__state">
        {done && scan.score !== null && (
          <span className="num" aria-label={`${t('scan.score')} ${scan.score}`}>
            {scan.score}
          </span>
        )}
        {done ? <ReleasePill status={scan.release_status!} /> : <ScanStatusPill status={scan.status} />}
      </span>
      <Icon name="chevronLeft" className="row__chevron" />
    </Link>
  );
}
