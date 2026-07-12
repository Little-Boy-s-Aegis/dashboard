import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const installIPBanFetchGuard = () => {
  const guardedWindow = window as Window & { __aegisFetchGuardInstalled?: boolean };
  if (guardedWindow.__aegisFetchGuardInstalled) return;
  guardedWindow.__aegisFetchGuardInstalled = true;

  const nativeFetch = window.fetch.bind(window);
  const isApiRequest = (input: RequestInfo | URL) => {
    const rawUrl = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.href
        : input.url;
    try {
      return new URL(rawUrl, window.location.origin).pathname.startsWith('/api/');
    } catch {
      return false;
    }
  };

  window.fetch = async (input, init) => {
    const requestInit = init ? { ...init } : undefined;
    const response = await nativeFetch(
      input,
      isApiRequest(input)
        ? { ...requestInit, credentials: requestInit?.credentials ?? 'include' }
        : requestInit
    );
    if (response.status === 403 && response.headers.get('X-Aegis-IP-Banned') === 'true') {
      window.localStorage.clear();
      window.sessionStorage.clear();
      window.dispatchEvent(new CustomEvent('aegis-ip-banned'));
    }
    return response;
  };
};

installIPBanFetchGuard();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
