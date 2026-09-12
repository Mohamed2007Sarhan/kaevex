import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// Remove the loading splash once React has mounted
if (typeof (window as any).__aegisReady === 'function') {
  (window as any).__aegisReady();
}
