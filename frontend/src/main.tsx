import './asaas-ui/styles/index.css';
import './styles/app.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { Ambient, ToastProvider } from './asaas-ui';
import { AuthProvider } from './lib/auth';
import { LangProvider } from './lib/lang';
import { OrgProvider } from './lib/org';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <LangProvider>
      <ToastProvider>
        <Ambient />
        <BrowserRouter>
          <AuthProvider>
            <OrgProvider>
              <App />
            </OrgProvider>
          </AuthProvider>
        </BrowserRouter>
      </ToastProvider>
    </LangProvider>
  </StrictMode>,
);

// The app has run for a while, so a later chunk failure may reload once again.
window.setTimeout(() => sessionStorage.removeItem('chunk-reload'), 10_000);
