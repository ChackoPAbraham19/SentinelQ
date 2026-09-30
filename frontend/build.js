'use strict';

const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const outputDirectory = path.join(__dirname, 'dist');
fs.mkdirSync(outputDirectory, { recursive: true });
fs.copyFileSync(path.join(__dirname, 'public', 'index.html'), path.join(outputDirectory, 'index.html'));
fs.copyFileSync(path.join(__dirname, 'public', 'runtime-config.js'), path.join(outputDirectory, 'runtime-config.js'));

esbuild.build({
  entryPoints: [path.join(__dirname, 'src', 'index.jsx')],
  outfile: path.join(outputDirectory, 'bundle.js'),
  bundle: true,
  minify: true,
  sourcemap: false,
  platform: 'browser',
  target: ['es2022'],
  loader: { '.js': 'jsx', '.jsx': 'jsx', '.css': 'css', '.woff': 'file', '.woff2': 'file' },
  assetNames: 'assets/[name]-[hash]',
  legalComments: 'none'
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
