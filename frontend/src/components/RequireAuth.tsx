import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { ErrorState, Skeleton } from '../asaas-ui';
import { useAuth } from '../lib/auth';
import { useOrg } from '../lib/org';

/** Signed-in pages only: waits for the session and the organizations, or sends the visitor to sign-in. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { org, loading, error, reload } = useOrg();
  const location = useLocation();

  if (user === null) {
    const next = location.pathname + location.search;
    return <Navigate to={next === '/' ? '/sign-in' : `/sign-in?next=${encodeURIComponent(next)}`} replace />;
  }
  if (user === undefined || (loading && !org)) {
    return (
      <div className="container page">
        <Skeleton count={3} height={120} />
      </div>
    );
  }
  if (error && !org) {
    return (
      <div className="container page">
        <ErrorState error={error} onRetry={reload} />
      </div>
    );
  }
  return <>{children}</>;
}
