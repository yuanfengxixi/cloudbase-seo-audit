'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = __dirname;
const out = path.join(root, '.build', 'seo-audit');
fs.mkdirSync(out, { recursive: true });
for (const name of ['index.js', 'shared-limit.cjs', 'config.json', 'package.json']) {
  fs.copyFileSync(path.join(root, 'cloud-function', name), path.join(out, name));
}
fs.copyFileSync(path.join(root, 'server.cjs'), path.join(out, 'server.cjs'));
const cleanupOut = path.join(root, '.build', 'seo-audit-rate-cleanup');
fs.mkdirSync(cleanupOut, { recursive: true });
for (const name of ['index.js', 'config.json', 'package.json']) {
  fs.copyFileSync(path.join(root, 'rate-cleanup', name), path.join(cleanupOut, name));
}
process.stdout.write(`CloudBase 云函数包已生成：${out}\n`);
