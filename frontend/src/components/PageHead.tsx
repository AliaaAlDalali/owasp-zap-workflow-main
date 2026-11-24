import type { ReactNode } from 'react';
import { Swash } from '../asaas-ui';

/** The page's one h1, an optional lead line, and its main actions. */
export function PageHead({ title, lead, actions, titleDir }: { title: string; lead?: ReactNode; actions?: ReactNode; titleDir?: 'ltr' }) {
  return (
    <header className="toolbar page-head">
      <div className="page-head__text">
        <h1 dir={titleDir}>{titleDir ? title : <Swash>{title}</Swash>}</h1>
        {lead && <p className="muted">{lead}</p>}
      </div>
      {actions && <div className="toolbar__actions cluster">{actions}</div>}
    </header>
  );
}
