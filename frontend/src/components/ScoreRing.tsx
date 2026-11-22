import { ProgressRing } from '../asaas-ui';
import { t } from '../content';

/** The 0–100 health score as a ring, the number in Sans. */
export function ScoreRing({ score, size = 152 }: { score: number; size?: number }) {
  return (
    <div role="img" aria-label={`${t('scan.score')}: ${score} ${t('scan.of100')}`}>
      <ProgressRing value={score} max={100} size={size}>
        <span className="score">
          <span className="score__value num">{score}</span>
          <span className="score__of">{t('scan.of100')}</span>
        </span>
      </ProgressRing>
    </div>
  );
}
