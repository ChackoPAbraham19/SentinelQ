import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import CustodianSetup from './CustodianSetup';
import '@fontsource/open-sans/latin-400.css';
import '@fontsource/open-sans/latin-600.css';
import '@fontsource/open-sans/latin-700.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import './styles.css';
import './portal.css';

const root = createRoot(document.getElementById('root'));
const setupToken = window.location.hash.match(/^#custodian-setup=([A-Za-z0-9_-]{43})$/)?.[1];
const api = window.SENTINELQ_CONFIG?.apiBaseUrl || (/^(localhost|127\.0\.0\.1)$/.test(window.location.hostname) ? 'http://127.0.0.1:4000' : window.location.origin);
root.render(setupToken ? <CustodianSetup token={setupToken} api={api} /> : <App />);
