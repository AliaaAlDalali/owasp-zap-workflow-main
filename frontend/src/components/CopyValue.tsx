import { Button, useToast } from '../asaas-ui';
import { t } from '../content';

/** A value the user must paste somewhere else (DNS record, file content), with a copy button. */
export function CopyValue({ label, value }: { label: string; value: string }) {
  const notify = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      notify(t('common.copied'));
    } catch {
      notify(t('api.error'), 'error');
    }
  };
  return (
    <div className="copy-value">
      <span className="copy-value__label">{label}</span>
      <div className="copy-value__box">
        <code dir="ltr">{value}</code>
        <Button variant="ghost" size="sm" icon="copy" label={`${t('common.copy')}: ${label}`} onClick={copy} />
      </div>
    </div>
  );
}
