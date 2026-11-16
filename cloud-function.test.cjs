'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

test('CloudBase package contains its runtime and matches the existing HTTP path', () => {
  execFileSync(process.execPath, [path.join(__dirname, 'package-cloud-function.cjs')]);
  const out = path.join(__dirname, '.build', 'seo-audit');
  for (const name of ['index.js', 'server.cjs', 'shared-limit.cjs', 'config.json', 'package.json']) assert.ok(fs.existsSync(path.join(out, name)), name);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'config.json'))).path, '/api/seo/audit');
  assert.ok(fs.existsSync(path.join(__dirname, '.build', 'seo-audit-rate-cleanup', 'index.js')));
});

test('CloudBase handler rejects invalid requests without starting a crawl', async () => {
  execFileSync(process.execPath, [path.join(__dirname, 'package-cloud-function.cjs')]);
  const { main } = require('./.build/seo-audit/index.js');
  const event = { path: '/api/seo/audit', requestContext: { sourceIp: '203.0.113.1' } };
  assert.equal((await main({ ...event, httpMethod: 'GET' })).statusCode, 405);
  assert.equal((await main({ ...event, httpMethod: 'POST', body: '{' })).statusCode, 400);
  assert.equal((await main({ ...event, httpMethod: 'POST', body: JSON.stringify({ url: 'http://127.0.0.1/' }) })).statusCode, 400);
  assert.equal((await main({ ...event, httpMethod: 'POST', body: 'x'.repeat(25 * 1024) })).statusCode, 413);
});

test('visitor limiter uses gateway-overwritten IP only with CloudBase request markers', () => {
  execFileSync(process.execPath, [path.join(__dirname, 'package-cloud-function.cjs')]);
  const { visitorIp } = require('./.build/seo-audit/index.js');
  const headers = { 'X-Real-IP': '8.8.8.8', 'X-Forwarded-For': '127.0.0.1' };
  assert.equal(visitorIp({ headers }), 'unknown');
  assert.equal(visitorIp({ headers, requestContext: { envId: 'env', requestId: 'req' } }), '8.8.8.8');
  assert.equal(visitorIp({ headers: { 'x-real-ip': 'bad' }, requestContext: { envId: 'env', requestId: 'req' } }), 'unknown');
});
