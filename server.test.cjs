'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createServer, parsePublicUrl, isPublicIp, htmlChecks, safeFetch, runAudit } = require('./server.cjs');

test('public URL parser rejects schemes, credentials, local hosts, and non-web ports', () => {
  for (const url of ['file:///etc/passwd', 'http://user:pass@example.com/', 'http://localhost/', 'http://127.0.0.1/', 'http://example.com:8080/']) {
    assert.throws(() => parsePublicUrl(url));
  }
  assert.equal(parsePublicUrl('https://example.com/path').hostname, 'example.com');
});

test('public IP classifier blocks private, loopback, link-local, documentation and reserved ranges', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '169.254.1.2', '172.16.2.3', '192.168.1.1', '100.64.0.1', '198.51.100.4', '203.0.113.8', '::1', 'fc00::1', 'fe80::1', '2001:db8::1']) assert.equal(isPublicIp(ip), false, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isPublicIp(ip), true, ip);
});

test('home-page checks report observed title, description, H1 and canonical', () => {
  const checks = htmlChecks('<title>Example</title><meta name="description" content="About"><h1>Hello</h1><link rel="canonical" href="https://example.com/">', 200);
  assert.deepEqual(checks.map((c) => c.status), ['passed', 'passed', 'passed', 'passed', 'passed']);
  assert.equal(htmlChecks('<html></html>', 503).filter((c) => c.status === 'critical').length, 5);
});

test('redirect targets are revalidated before a connection, including fresh DNS results', async () => {
  let dnsCalls = 0;
  let redirectLookups = 0;
  const resolver = { async lookup(host) {
    dnsCalls++;
    if (host === 'public.example') return [{ address: '8.8.8.8', family: 4 }];
    if (host === 'redirect.example') return ++redirectLookups === 1
      ? [{ address: '8.8.4.4', family: 4 }]
      : [{ address: '127.0.0.1', family: 4 }];
    throw new Error('unexpected host');
  } };
  let requests = 0;
  await assert.rejects(safeFetch('https://public.example/', resolver, 0, async () => {
    requests++;
    return { status: 302, location: 'http://127.0.0.1/admin' };
  }));
  assert.equal(requests, 1, 'private literal redirect must never be requested');

  dnsCalls = 0; redirectLookups = 0; requests = 0;
  await assert.rejects(safeFetch('https://public.example/', resolver, 0, async () => {
    requests++;
    return { status: 302, location: 'https://redirect.example/' };
  }));
  assert.equal(requests, 2, 'redirect hostname resolving to a private IP on recheck must not be requested again');
  assert.equal(redirectLookups, 2, 'redirect destination DNS is resolved independently on every hop');
});

test('free audit samples at most two same-origin pages and respects conservative robots rules', async () => {
  const resolver = { lookup: async () => [{ address: '8.8.8.8', family: 4 }] };
  const requested = [];
  const requestFn = async (url) => {
    requested.push(url.pathname);
    if (url.pathname === '/') return { status: 200, body: '<title>Home</title><meta name="description" content="Home"><h1>Home</h1><a href="/about/"><a href="https://elsewhere.example/"><a href="/contact/"><a href="/third/">' };
    if (url.pathname === '/robots.txt') return { status: 200, body: 'User-agent: *\nAllow: /' };
    if (url.pathname === '/sitemap.xml') return { status: 200, body: '<urlset></urlset>' };
    return { status: 200, body: '<title>Page</title><meta name="description" content="Page"><h1>Page</h1>' };
  };
  const result = await runAudit('https://example.com/', resolver, requestFn);
  assert.equal(result.checks.find((c) => c.id === 'sample_pages').status, 'passed');
  assert.deepEqual(requested, ['/', '/robots.txt', '/sitemap.xml', '/about/', '/contact/']);
  const blocked = await runAudit('https://example.com/', resolver, async (url) => url.pathname === '/robots.txt'
    ? { status: 200, body: 'User-agent: *\nDisallow: /private' }
    : requestFn(url));
  assert.match(blocked.checks.find((c) => c.id === 'sample_pages').detail, /只检查首页/);
});

test('resource probes reject soft-200 HTML and follow same-origin sitemap directives', async () => {
  const resolver = { lookup: async () => [{ address: '8.8.8.8', family: 4 }] };
  const html = '<title>Home</title><meta name="description" content="Home"><h1>Home</h1><a href="/about/">';
  const soft = await runAudit('https://example.com/', resolver, async (url) => ({ status: 200, body: url.pathname === '/' ? html : '<html><title>Missing</title></html>' }));
  assert.equal(soft.checks.find((c) => c.id === 'robots').status, 'warning');
  assert.equal(soft.checks.find((c) => c.id === 'sitemap').status, 'warning');
  assert.match(soft.checks.find((c) => c.id === 'sample_pages').detail, /未抓取/);
  const requested = [];
  const custom = await runAudit('https://example.com/', resolver, async (url) => {
    requested.push(url.pathname);
    if (url.pathname === '/') return { status: 200, body: html };
    if (url.pathname === '/robots.txt') return { status: 200, body: 'User-agent: *\nSitemap: https://example.com/map.xml' };
    if (url.pathname === '/map.xml') return { status: 200, body: '<?xml version="1.0"?><urlset><url></url></urlset>' };
    return { status: 200, body: '<title>About</title><meta name="description" content="About">' };
  });
  assert.ok(requested.includes('/map.xml'));
  assert.ok(!requested.includes('/sitemap.xml'));
  assert.equal(custom.checks.find((c) => c.id === 'sitemap').status, 'passed');
});

test('HTTP endpoint returns method, validation, body-size and rate-limit responses', async (t) => {
  const server = createServer({ now: 10_000 });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/seo/audit`;
  const request = (method, body = '') => new Promise((resolve, reject) => {
    const req = http.request(base, { method, headers: { 'content-type': 'application/json' } }, (res) => {
      let text = ''; res.setEncoding('utf8'); res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
    });
    req.on('error', reject); req.end(body);
  });
  assert.equal((await request('GET')).status, 405);
  assert.equal((await request('POST', JSON.stringify({ url: 'http://127.0.0.1/' }))).status, 400);
  assert.equal((await request('POST', 'x'.repeat(25 * 1024))).status, 413);
  for (let i = 0; i < 8; i++) await request('POST', JSON.stringify({ url: 'http://127.0.0.1/' }));
  assert.equal((await request('POST', JSON.stringify({ url: 'http://127.0.0.1/' }))).status, 429);
});
