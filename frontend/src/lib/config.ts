// The only file that reads import.meta.env. Everything here is public.
export const config = {
  apiBase: import.meta.env.VITE_API_BASE ?? '/api',
} as const;
