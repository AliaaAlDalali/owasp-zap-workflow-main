import { Link } from 'react-router-dom';
import { Card, EmptyState } from '../asaas-ui';
import { t } from '../content';
import { usePageMeta } from '../lib/usePageMeta';

export default function NotFound() {
  usePageMeta(t('notFound.title'));
  return (
    <div className="page">
      <Card>
        <EmptyState icon="search" title={t('notFound.title')}>
          <p className="subtle">{t('notFound.body')}</p>
          <Link to="/" className="btn btn--primary">
            {t('notFound.home')}
          </Link>
        </EmptyState>
      </Card>
    </div>
  );
}
