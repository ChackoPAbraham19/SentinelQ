'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const root = path.join(__dirname, 'dist');
const build = spawn(process.execPath, [path.join(__dirname, 'build.js')], { stdio: 'inherit' });
build.on('exit', code => {
  if (code !== 0) return process.exit(code || 1);
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const filePath = path.resolve(root, relative);
    if (!filePath.startsWith(`${root}${path.sep}`) && filePath !== path.join(root, 'index.html')) {
      res.writeHead(403); return res.end('Forbidden');
    }
    const selected = fs.existsSync(filePath) && fs.statSync(filePath).isFile() ? filePath : path.join(root, 'index.html');
    const extension = path.extname(selected);
    const type = extension === '.html' ? 'text/html; charset=utf-8' : extension === '.js' ? 'text/javascript; charset=utf-8' : extension === '.css' ? 'text/css; charset=utf-8' : extension === '.woff2' ? 'font/woff2' : extension === '.woff' ? 'font/woff' : 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': extension === '.html' ? 'no-store' : 'no-cache',
      'Content-Security-Policy': "default-src 'self'; connect-src http://127.0.0.1:4000 http://localhost:4000; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    });
    fs.createReadStream(selected).pipe(res);
  }).listen(3000, '127.0.0.1', () => console.log('SentinelQ frontend: http://localhost:3000'));
});
