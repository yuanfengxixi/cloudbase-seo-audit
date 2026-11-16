'use strict';
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');

const MAX_BODY = 24 * 1024;
const MAX_RESPONSE = 512 * 1024;
const TIMEOUT_MS = 7000;
const DNS_TIMEOUT_MS = 3500;
const AUDIT_TIMEOUT_MS = 20_000;
const MAX_REDIRECTS = 3;
const MAX_CONCURRENT_AUDITS = 5;
const WINDOW_MS = 60_000;
const RATE_LIMIT = 10;
const buckets = new Map();
let activeAudits = 0;
function withTimeout(promise, ms, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    Promise.resolve(promise).then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function inCidr(ip, base, bits) {
  const a = ip.split('.').reduce((n, part) => (n * 256 + Number(part)) >>> 0, 0);
  const b = base.split('.').reduce((n, part) => (n * 256 + Number(part)) >>> 0, 0);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}
const V4_DENY = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
function isPublicIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return !V4_DENY.some(([base, bits]) => inCidr(ip, base, bits));
  if (family !== 6) return false;
  const s = ip.toLowerCase().split('%')[0];
  if (s.startsWith('::ffff:')) {
    const mapped = s.slice(7);
    return net.isIP(mapped) === 4 && isPublicIp(mapped);
  }
  // Permit globally routed unicast 2000::/3 only; excludes loopback, ULA, link-local,
  // IPv4-compatible and other special-use ranges by construction.
  const first = parseInt(s.split(':')[0] || '0', 16);
  if ((first & 0xe000) !== 0x2000) return false;
  if (s.startsWith('2001:') && !s.startsWith('2001:4860:') && !s.startsWith('2001:4861:')) return false;
  if (s.startsWith('2002:') || s.startsWith('3fff:')) return false;
  return true;
}

async function resolvePublic(hostname, resolver = dns) {
  if (net.isIP(hostname)) {
    if (!isPublicIp(hostname)) throw new Error('目标地址不是可公开访问的 IP。');
    return [{ address: hostname, family: net.isIP(hostname) }];
  }
  const records = await resolver.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((r) => !isPublicIp(r.address))) throw new Error('域名解析到不可公开访问的地址。');
  return records;
}
function parsePublicUrl(value) {
  let url;
  try { url = new URL(value); } catch (_) { throw new Error('请输入有效的网站首页地址。'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('仅支持不含账号信息的 HTTP 或 HTTPS 公开网址。');
  if (url.port && !['80', '443'].includes(url.port)) throw new Error('仅支持网站标准端口 80 或 443。');
  if (!url.hostname || url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.local')) throw new Error('请输入公开网站域名。');
  if (net.isIP(url.hostname) && !isPublicIp(url.hostname)) throw new Error('目标地址不是可公开访问的 IP。');
  return url;
}
function boundedRequest(url, addresses) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const selected = addresses[0];
    const options = {
      method: 'GET', headers: { 'user-agent': 'CloudBaseSeoAudit/1.0 (+https://github.com/yuanfengxixi/cloudbase-seo-audit)', accept: 'text/html,text/plain,application/xml,*/*;q=0.3' },
      timeout: TIMEOUT_MS,
      lookup: (_host, lookupOptions, cb) => {
        // Node's lookup callback changes shape when `all: true` is requested.
        // Return only the already validated DNS answers so the socket remains pinned.
        if (lookupOptions && typeof lookupOptions === 'object' && lookupOptions.all) cb(null, addresses);
        else cb(null, selected.address, selected.family);
      },
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
    };
    const req = transport.request(url, options, (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        res.resume(); resolve({ status, location: res.headers.location }); return;
      }
      const chunks = []; let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE) { req.destroy(new Error('网站响应超过检查上限。')); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({ status, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('访问网站超时。')));
    req.on('error', reject);
    req.end();
  });
}
async function safeFetch(input, resolver = dns, redirects = 0, requestFn = boundedRequest, allowedOrigin = '') {
  const url = parsePublicUrl(String(input));
  if (allowedOrigin && url.origin !== allowedOrigin) throw new Error('资源跳转离开原网站，已停止抓取。');
  const addresses = await withTimeout(resolvePublic(url.hostname, resolver), DNS_TIMEOUT_MS, '域名解析超时。');
  const result = await requestFn(url, addresses);
  if (result.location) {
    if (redirects >= MAX_REDIRECTS) throw new Error('网站跳转次数过多。');
    const next = new URL(result.location, url);
    // Every hop is re-parsed, DNS checked, and pinned before connecting.
    return safeFetch(next.href, resolver, redirects + 1, requestFn, allowedOrigin);
  }
  return { url, ...result };
}
function htmlChecks(html, status) {
  const checks = [];
  const add = (id, label, pass, detail) => checks.push({ id, label, status: pass === null ? 'warning' : pass ? 'passed' : 'critical', detail });
  add('home_status', '首页可访问', status >= 200 && status < 400, `首页返回 HTTP ${status}。`);
  const title = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html)?.[1]?.replace(/<[^>]+>/g, '').trim();
  add('title', '页面标题', Boolean(title), title ? `已检测到标题：“${title.slice(0, 180)}”。` : '未检测到 title 元素或其内容为空。');
  const description = /<meta\b(?=[^>]*\bname\s*=\s*["']description["'])(?=[^>]*\bcontent\s*=\s*["']([^"']*)["'])[^>]*>/i.exec(html)?.[1]?.trim();
  add('description', '页面描述', Boolean(description), description ? `已检测到页面描述（${description.length} 个字符）。` : '未检测到带有内容的 meta description。');
  const h1Count = [...html.matchAll(/<h1\b[^>]*>/gi)].length;
  add('h1', '一级标题', h1Count === 1, `检测到 ${h1Count} 个 h1 元素。`);
  const canonical = /<link\b(?=[^>]*\brel\s*=\s*["']canonical["'])(?=[^>]*\bhref\s*=\s*["']([^"']+)["'])[^>]*>/i.exec(html)?.[1];
  add('canonical', '规范链接', Boolean(canonical), canonical ? `检测到规范链接：${canonical.slice(0, 240)}` : '未检测到 canonical 链接。');
  return checks;
}
async function ancillaryCheck(url, resolver, path, id, label, requestFn) {
  try {
    const target = new URL(path, url);
    const result = await safeFetch(target.href, resolver, 0, requestFn, url.origin);
    const httpOk = result.status >= 200 && result.status < 300;
    const body = String(result.body || '');
    const looksHtml = /<\s*(?:!doctype\s+html|html|head|body)\b/i.test(body.slice(0, 1000));
    const formatOk = id === 'robots'
      ? !looksHtml && (!body.trim() || /^\s*(?:user-agent|sitemap|allow|disallow|host)\s*:/im.test(body))
      : !looksHtml && /<\s*(?:[\w-]+:)?(?:urlset|sitemapindex)\b/i.test(body.slice(0, 4096));
    const pass = httpOk && formatOk;
    const detail = !httpOk ? `资源返回 HTTP ${result.status}。` : pass
      ? `资源返回 HTTP ${result.status}，内容格式符合基础检查。`
      : `资源返回 HTTP ${result.status}，但内容不像有效的 ${id === 'robots' ? 'robots.txt' : 'Sitemap'} 文件。`;
    return { check: { id, label, status: pass ? 'passed' : 'warning', detail }, result };
  } catch (error) { return { check: { id, label, status: 'warning', detail: `无法确认：${error.message}` }, result: null }; }
}
function sitemapTarget(homeUrl, robots) {
  const matches = String(robots.result?.body || '').matchAll(/^\s*sitemap\s*:\s*(\S+)/gim);
  for (const match of matches) {
    try {
      const target = new URL(match[1]);
      if (target.origin === homeUrl.origin && ['http:', 'https:'].includes(target.protocol)) return target.href;
    } catch (_) { /* Ignore malformed directives. */ }
  }
  return '/sitemap.xml';
}
function sampleLinks(html, homeUrl) {
  const links = [];
  const seen = new Set([homeUrl.pathname]);
  for (const match of html.matchAll(/<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1/gi)) {
    let url;
    try { url = new URL(match[2], homeUrl); } catch (_) { continue; }
    if (url.origin !== homeUrl.origin || url.search || url.username || url.password || seen.has(url.pathname)) continue;
    if (/\/(?:api|logout|delete|unsubscribe)(?:\/|$)/i.test(url.pathname)) continue;
    if (/\.[a-z0-9]{2,6}$/i.test(url.pathname) && !/\.html?$/i.test(url.pathname)) continue;
    seen.add(url.pathname);
    url.hash = '';
    links.push(url.href);
    if (links.length === 2) break;
  }
  return links;
}
async function samplePageCheck(home, robots, resolver, requestFn) {
  const id = 'sample_pages';
  const label = '少量公开页面抽查';
  const robotStatus = robots.result?.status;
  if (robotStatus !== 404 && robotStatus !== 200) return { id, label, status: 'warning', detail: '无法确认 robots.txt 规则，本次未抓取其他页面。' };
  if (robotStatus === 200 && robots.check.status !== 'passed') return { id, label, status: 'warning', detail: 'robots.txt 内容无法确认，本次未抓取其他页面。' };
  if (robotStatus === 200 && /^\s*disallow\s*:\s*\S+/im.test(robots.result.body || '')) return { id, label, status: 'warning', detail: 'robots.txt 含抓取限制，为避免误抓取，本次只检查首页。' };
  const links = sampleLinks(home.body || '', home.url);
  if (!links.length) return { id, label, status: 'warning', detail: '首页未发现适合抽查的同站公开页面链接。' };
  let checked = 0;
  let issues = 0;
  for (const link of links) {
    try {
      const page = await safeFetch(link, resolver, 0, requestFn, home.url.origin);
      checked++;
      if (page.status < 200 || page.status >= 400 || htmlChecks(page.body || '', page.status).some((c) => ['title', 'description'].includes(c.id) && c.status !== 'passed')) issues++;
    } catch (_) { issues++; }
  }
  return { id, label, status: issues ? 'warning' : 'passed', detail: `抽查 ${links.length} 个同站页面，成功读取 ${checked} 个；其中 ${issues} 个存在访问或标题、描述问题。` };
}
async function runAudit(rawUrl, resolver = dns, requestFn = boundedRequest) {
  const home = await safeFetch(rawUrl, resolver, 0, requestFn);
  const checks = htmlChecks(home.body || '', home.status);
  const robots = await ancillaryCheck(home.url, resolver, '/robots.txt', 'robots', 'robots.txt 可访问', requestFn);
  const [sitemap, sample] = await Promise.all([
    ancillaryCheck(home.url, resolver, sitemapTarget(home.url, robots), 'sitemap', '站点地图可访问', requestFn),
    samplePageCheck(home, robots, resolver, requestFn),
  ]);
  checks.push(robots.check, sitemap.check, sample);
  const count = (status) => checks.filter((c) => c.status === status).length;
  return { url: home.url.href, checks, summary: { critical: count('critical'), warning: count('warning'), passed: count('passed') } };
}
function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(body);
}
function rateLimited(key, now = Date.now()) {
  for (const [ip, bucket] of buckets) if (now - bucket.start >= WINDOW_MS) buckets.delete(ip);
  let bucket = buckets.get(key);
  if (!bucket || now - bucket.start >= WINDOW_MS) { bucket = { start: now, count: 0 }; buckets.set(key, bucket); }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT;
}
async function handleAudit(req, res, options = {}) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: { code: 'method_not_allowed', message: '仅支持 POST 请求。' } });
  const address = req.socket?.remoteAddress || 'unknown';
  if (rateLimited(address, options.now)) return sendJson(res, 429, { error: { code: 'rate_limited', message: '请求过于频繁，请稍后再试。' } });
  let body = '';
  try {
    for await (const chunk of req) {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY) return sendJson(res, 413, { error: { code: 'body_too_large', message: '请求内容过大。' } });
    }
    const data = JSON.parse(body);
    if (typeof data.url !== 'string' || data.url.length > 2048) return sendJson(res, 400, { error: { code: 'invalid_url', message: '请提供有效的网站地址。' } });
    if (activeAudits >= MAX_CONCURRENT_AUDITS) return sendJson(res, 503, { error: { code: 'busy', message: '当前检测请求较多，请稍后重试。' } });
    activeAudits += 1;
    const audit = runAudit(data.url, options.resolver || dns, options.requestFn || boundedRequest);
    // Keep the slot occupied until the underlying work ends, even if the HTTP response timed out.
    audit.then(() => { activeAudits -= 1; }, () => { activeAudits -= 1; });
    const result = await withTimeout(audit, AUDIT_TIMEOUT_MS, '检测时间较长，本次已停止等待，请稍后重试。');
    return sendJson(res, 200, result);
  } catch (error) {
    const status = /请输入|仅支持|公开网站|标准端口|不可公开|不可访问的地址|不是可公开访问/.test(error.message) ? 400 : 502;
    return sendJson(res, status, { error: { code: status === 400 ? 'invalid_url' : 'audit_failed', message: error.message || '检测未完成。' } });
  }
}
function createServer(options = {}) {
  return http.createServer((req, res) => {
    let path;
    try { path = new URL(req.url, 'http://localhost').pathname; } catch (_) { path = ''; }
    if (path !== '/api/seo/audit') return sendJson(res, 404, { error: { code: 'not_found', message: '未找到接口。' } });
    handleAudit(req, res, options);
  });
}
module.exports = { createServer, handleAudit, runAudit, safeFetch, parsePublicUrl, isPublicIp, resolvePublic, htmlChecks };
