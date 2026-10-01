'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Serve only built public assets, never project files or the evidence vault.
function createFrontend(root) {
  const directory = path.resolve(root);
  const headers = {
    'Content-Security-Policy': "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self'; script-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=()',
    'Cache-Control': 'no-cache',
  };
  return async function serve(req, res, pathname) {
    if (!['GET', 'HEAD'].includes(req.method)) return false;
    if (pathname === '/runtime-config.js') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : 'window.SENTINELQ_CONFIG = {apiBaseUrl: window.location.origin};');
      return true;
    }
    const relative = pathname === '/' || pathname === '/index.html' ? 'index.html'
      : /^\/(bundle\.(?:js|css)|assets\/[a-zA-Z0-9_-]+\.(?:woff2?|png|svg|jpg))$/.test(pathname) ? pathname.slice(1) : null;
    if (!relative) return false;
    const filename = path.resolve(directory, relative);
    if (!filename.startsWith(directory + path.sep)) return false;
    let bytes;
    try { bytes = await fs.promises.readFile(filename); }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    const type = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff': 'font/woff', '.woff2': 'font/woff2', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml' }[path.extname(filename)];
    res.writeHead(200, { ...headers, 'Content-Type': type, 'Content-Length': bytes.length });
    res.end(req.method === 'HEAD' ? undefined : bytes);
    return true;
  };
}
module.exports = { createFrontend };
