import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const installIPBanFetchGuard = () => {
  const guardedWindow = window as Window & { __aegisFetchGuardInstalled?: boolean };
  if (guardedWindow.__aegisFetchGuardInstalled) return;
  guardedWindow.__aegisFetchGuardInstalled = true;

  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await nativeFetch(...args);
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
