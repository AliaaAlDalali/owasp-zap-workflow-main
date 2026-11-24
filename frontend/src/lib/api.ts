import { useCallback, useEffect, useState } from 'react';
import { t } from '../content';
import { config } from './config';
import { getLang } from './lang';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized: () => void = () => {};

/** AuthProvider registers what a 401 does (clear the user, go to sign-in). */
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

/** The only place that calls fetch. Sends the session cookie and the language. */
export async function request<T>(path: string, init?: RequestInit & { skipAuthRedirect?: boolean }): Promise<T> {
  const { skipAuthRedirect, ...rest } = init ?? {};
  const headers = new Headers(rest.headers);
  headers.set('X-Lang', getLang());
  if (rest.body && !(rest.body instanceof FormData)) headers.set('Content-Type', 'application/json');

  let response: Response;
  try {
    response = await fetch(`${config.apiBase}${path}`, { ...rest, headers, credentials: 'include' });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(t('api.error'), 0);
  }

  const body = response.status === 204 ? null : await response.json().catch(() => null);
  if (response.status === 401 && !skipAuthRedirect) onUnauthorized();
  if (!response.ok) {
    const message = body && typeof body.message === 'string' ? body.message : t('api.error');
    throw new ApiError(message, response.status);
  }
  return body as T;
}

export const post = <T>(path: string, data?: unknown) =>
  request<T>(path, { method: 'POST', body: data === undefined ? undefined : JSON.stringify(data) });

export const remove = (path: string) => request<null>(path, { method: 'DELETE' });

interface ApiState<T> {
  data?: T;
  error?: unknown;
  loading: boolean;
}

/**
 * Loads `path` (or nothing while it is null). `reload()` fetches again; a quiet
 * reload keeps the current data on screen instead of showing the skeleton.
 */
export function useApi<T>(path: string | null) {
  const [state, setState] = useState<ApiState<T>>({ loading: Boolean(path) });
  const [attempt, setAttempt] = useState({ n: 0, quiet: false });

  useEffect(() => {
    if (!path) return;
    const controller = new AbortController();
    if (!attempt.quiet) setState((s) => ({ ...s, loading: true, error: undefined }));
    request<T>(path, { signal: controller.signal })
      .then((data) => setState({ data, loading: false }))
      .catch((error) => {
        if (!controller.signal.aborted) setState((s) => ({ ...s, error, loading: false }));
      });
    return () => controller.abort(); // path changed or the component left: drop the old answer
  }, [path, attempt]);

  const reload = useCallback((quiet = false) => setAttempt((a) => ({ n: a.n + 1, quiet })), []);
  return { ...state, reload };
}
