import { lazy, Suspense } from 'react';
import { Route, Routes } from 'react-router-dom';
import { Skeleton } from './asaas-ui';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Layout } from './components/Layout';
import { RequireAuth } from './components/RequireAuth';
import { useLang } from './lib/lang';
import Home from './pages/Home';

const SignIn = lazy(() => import('./pages/SignIn'));
const Sites = lazy(() => import('./pages/Sites'));
const SiteDetail = lazy(() => import('./pages/SiteDetail'));
const Scans = lazy(() => import('./pages/Scans'));
const ScanDetail = lazy(() => import('./pages/ScanDetail'));
const Compare = lazy(() => import('./pages/Compare'));
const Settings = lazy(() => import('./pages/Settings'));
const NotFound = lazy(() => import('./pages/NotFound'));

const fallback = (
  <div className="container page">
    <Skeleton count={3} height={120} />
  </div>
);

export default function App() {
  // Remount the pages when the language changes so every component re-reads its text.
  const { lang } = useLang();
  return (
    <ErrorBoundary key={lang}>
      <Suspense fallback={fallback}>
        <Routes>
          <Route path="sign-in" element={<SignIn />} />
          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Home />} />
            <Route path="sites" element={<Sites />} />
            <Route path="sites/:id" element={<SiteDetail />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="scans/:id/compare" element={<Compare />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
