import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import '@fontsource/open-sans/latin-400.css';
import '@fontsource/open-sans/latin-600.css';
import '@fontsource/open-sans/latin-700.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import './styles.css';
import './portal.css';

const root = createRoot(document.getElementById('root'));
root.render(<App />);
