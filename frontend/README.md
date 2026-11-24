# Himaak (حِماك) Platform web app

The front end of the Himaak SaaS. People sign in, add their sites, prove they own them, request OWASP ZAP scans, and read each report: the health score, the release decision, findings with remediation code, and a comparison with the previous scan.

Built to the ASAAS frontend standard with the `asaas-ui` kit:
- React, TypeScript, Vite and `react-router-dom`.
- Arabic right-to-left first, with English.
- Designed for phones first: a header plus a bottom tab bar at 900px and below.
- Light and dark themes.

## Run

Start the API first (see `backend/README.md`; use `COOKIE_SECURE=false` for local http). Then:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

**Fonts.** The Thmanyah font files are not in this repository: their licence allows embedding them in the product, not publishing them in a public repo. Copy the kit's font folder in before building for production (do not re-run the kit installer: it skips an existing `src/asaas-ui` and rewrites `index.html`):

```bash
cp -r "<asaas-ui skill folder>/template/src/asaas-ui/fonts/thmanyah" frontend/src/asaas-ui/fonts/
```

Without the fonts the app still builds and runs, with the system font instead.

The dev server forwards `/api/*` to the API at `http://127.0.0.1:8000`, so the session cookie stays same-origin. To use another address, set `HIMAAK_API_TARGET`.

Other commands:
- `npm run build` type-checks and builds to `dist/`.
- `npm run lint` runs oxlint.

## Production

Serve `dist/` and the API from **one origin**, with a reverse proxy that sends `/api/` to the API and strips the prefix. That keeps the `HttpOnly; Secure; SameSite=Lax` session cookie first-party, so no CORS is needed.
- Return `index.html` for page routes.
- Serve `assets/` with a long immutable cache, and `index.html` and `theme-init.js` with `no-cache`.

`VITE_API_BASE` (default `/api`) is the only build setting; see `.env.example`.

## Layout

```text
src/
├── asaas-ui/     the ASAAS kit (owned by this project; fonts not in git, see above; adds the shield, globe, refresh, copy and compare icons, and Stat's `unit`)
├── components/   Layout (header, tab bar), RequireAuth, ErrorBoundary, status pills, score ring, finding inspector
├── pages/        one lazy-loaded file per route
├── content/      ar.ts and en.ts dictionaries (same keys, enforced by the type check) and t()
├── lib/          API client and useApi, auth, organization, language, safeHref, page titles, date format
├── styles/       app.css on top of the kit
├── App.tsx       routes
└── main.tsx      providers
```

## Routes

| Path | Page |
| --- | --- |
| `/sign-in` | Sign in or create an account (with a new organization). Returns to `?next=` afterwards. |
| `/` | Overview: counts, recent scans, latest completed scan. |
| `/sites`, `/sites/:id` | Sites, adding a site, ownership proof (DNS TXT or file), scan history, starting a scan, deleting (owner only). |
| `/scans`, `/scans/:id` | All scans; a report page that refreshes itself while a scan is queued or running. |
| `/scans/:id/compare` | New, fixed and still-open findings compared with the previous scan of the site. |
| `/settings` | Switching organization, members (owner adds), new organization, signing out. |

## Notes

- Error messages from the API are in Arabic only for now. The client already sends `X-Lang`, so the API can return English messages later.
- Finding descriptions and solutions come from ZAP in English. Names and remediation code come from Himaak's Arabic knowledge base.
