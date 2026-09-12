import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// AegisCore Dashboard — Vite Configuration
// Dashboard runs on  :3000
// Backend API is on  :9009  (proxied to avoid CORS in production builds)
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '127.0.0.1',   // localhost only — no LAN exposure unless needed
    open: false,          // tray.js handles browser opening
    proxy: {
      // In dev mode forward /api → AegisCore C backend on :9009
      '/api': {
        target: 'http://127.0.0.1:9009',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    port: 3000,
    host: '127.0.0.1',
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react:  ['react', 'react-dom'],
          motion: ['framer-motion'],
          icons:  ['lucide-react'],
        },
      },
    },
  },
  define: {
    __AEGISCORE_VERSION__: JSON.stringify('9.0.0'),
    __BUILD_DATE__:        JSON.stringify(new Date().toISOString()),
  },
});
