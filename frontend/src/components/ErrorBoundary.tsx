import { Component, type ReactNode } from 'react';
import { ErrorState } from '../asaas-ui';
import { t } from '../content';

/** Keeps a crash from blanking the app. A failed lazy chunk (after a deploy) reloads once. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: unknown }> {
  state = { error: null as unknown };

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  componentDidCatch(error: unknown) {
    const chunkFailed =
      error instanceof Error && /dynamically imported module|Loading chunk|Importing a module script failed/i.test(error.message);
    if (chunkFailed && !sessionStorage.getItem('chunk-reload')) {
      sessionStorage.setItem('chunk-reload', '1');
      location.reload();
    }
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="container page">
        <ErrorState error={new Error(t('error.page'))} onRetry={() => location.reload()} />
      </div>
    );
  }
}
