import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from 'react';
import { useApi } from './api';
import { useAuth } from './auth';
import type { Organization } from './types';

const KEY = 'himaak-org';

function savedOrgId(): number | null {
  try {
    const value = Number(localStorage.getItem(KEY));
    return Number.isInteger(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

interface OrgValue {
  /** The organization the pages work in; null while loading or when the user has none. */
  org: Organization | null;
  orgs: Organization[];
  loading: boolean;
  error: unknown;
  setOrgId: (id: number) => void;
  reload: () => void;
}

const OrgContext = createContext<OrgValue | null>(null);

/** The signed-in user's organizations and the one currently selected. */
export function OrgProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const { data, loading, error, reload } = useApi<Organization[]>(user ? '/organizations' : null);
  const [selected, setSelected] = useState<number | null>(savedOrgId);

  const setOrgId = useCallback((id: number) => {
    setSelected(id);
    try {
      localStorage.setItem(KEY, String(id));
    } catch {
      /* storage unavailable: the choice lasts for this visit */
    }
  }, []);

  const value = useMemo<OrgValue>(() => {
    const orgs = user ? (data ?? []) : [];
    const org = orgs.find((o) => o.id === selected) ?? orgs[0] ?? null;
    return { org, orgs, loading: Boolean(user) && loading, error, setOrgId, reload: () => reload(true) };
  }, [user, data, loading, error, selected, setOrgId, reload]);

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg(): OrgValue {
  const value = useContext(OrgContext);
  if (!value) throw new Error('useOrg must be used inside OrgProvider');
  return value;
}

/** Path prefix for the current organization's endpoints. */
export function useOrgPath(): string | null {
  const { org } = useOrg();
  return org ? `/organizations/${org.id}` : null;
}
