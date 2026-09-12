/**
 * AegisCore v1 — Production Static Server
 * Serves the built React dashboard on port 3000
 *
 * Usage: node serve-dashboard.js
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT     = 3000;
const DIST_DIR = path.join(__dirname, 'dashboard');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.json': 'application/json',
  '.woff2':'font/woff2',
  '.woff': 'font/woff',
  '.ttf':  'font/ttf',
  '.map':  'application/json',
};

const server = http.createServer((req, res) => {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';

  let filePath = path.join(DIST_DIR, urlPath);

  // SPA fallback — all non-asset routes serve index.html
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(DIST_DIR, 'index.html');
  }

  const ext  = path.extname(filePath).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404); res.end('Not found'); return;
    }
    const headers = { 'Content-Type': mime };
    // Cache assets forever, HTML never
    if (urlPath.startsWith('/assets/')) headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    else headers['Cache-Control'] = 'no-cache';
    res.writeHead(200, headers);
    res.end(data);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[AegisCore Dashboard] Serving on http://localhost:${PORT}`);
  console.log(`[AegisCore Dashboard] Dist: ${DIST_DIR}`);
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`[Error] Port ${PORT} already in use`);
  else throw err;
});
