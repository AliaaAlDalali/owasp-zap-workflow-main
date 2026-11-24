import { Icon, type IconName } from '../asaas-ui';
import { t, type TextKey } from '../content';
import type { ReleaseStatus, RiskCode, ScanStatus } from '../lib/types';

// State is always icon + label, never colour alone.
type Tone = 'paid' | 'partial' | 'unpaid' | 'neutral';

function Pill({ tone, icon, label }: { tone: Tone; icon: IconName; label: string }) {
  return (
    <span className={`pill pill--${tone}`}>
      <Icon name={icon} />
      {label}
    </span>
  );
}

const RISK: Record<RiskCode, { tone: Tone; icon: IconName }> = {
  3: { tone: 'unpaid', icon: 'alert' },
  2: { tone: 'partial', icon: 'alert' },
  1: { tone: 'neutral', icon: 'eye' },
  0: { tone: 'neutral', icon: 'file' },
};

export function RiskPill({ risk }: { risk: RiskCode }) {
  return <Pill {...RISK[risk]} label={t(`risk.${risk}` as TextKey)} />;
}

const RELEASE: Record<ReleaseStatus, { tone: Tone; icon: IconName }> = {
  approved: { tone: 'paid', icon: 'checkCircle' },
  conditional: { tone: 'partial', icon: 'clock' },
  blocked: { tone: 'unpaid', icon: 'alert' },
};

export function ReleasePill({ status }: { status: ReleaseStatus }) {
  return <Pill {...RELEASE[status]} label={t(`release.${status}`)} />;
}

const SCAN: Record<ScanStatus, { tone: Tone; icon: IconName }> = {
  queued: { tone: 'neutral', icon: 'clock' },
  running: { tone: 'partial', icon: 'refresh' },
  completed: { tone: 'paid', icon: 'checkCircle' },
  failed: { tone: 'unpaid', icon: 'alert' },
};

export function ScanStatusPill({ status }: { status: ScanStatus }) {
  return <Pill {...SCAN[status]} label={t(`status.${status}`)} />;
}

export function VerifiedPill({ verified }: { verified: boolean }) {
  return verified ? (
    <Pill tone="paid" icon="checkCircle" label={t('sites.verified')} />
  ) : (
    <Pill tone="partial" icon="clock" label={t('sites.pending')} />
  );
}
