'use strict';
const { runAudit, parsePublicUrl } = require('./server.cjs');
const { checkSharedLimit } = require('./shared-limit.cjs');
const net = require('node:net');

const MAX_BODY = 24 * 1024;
const MAX_ACTIVE = 5;
const MAX_PER_MINUTE = 10;
const buckets = new Map();
let active = 0;
let loggedIpSource = false;

function reply(statusCode, data) {
  return { statusCode, headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  }, body: JSON.stringify(data) };
}
function header(headers, name) {
  const key = Object.keys(headers || {}).find((item) => item.toLowerCase() === name);
  return key ? String(headers[key]) : '';
}
function visitorIpSource(event) {
  if (typeof event.requestContext?.identity?.sourceIp === 'string' && event.requestContext.identity.sourceIp) return 'requestContext.identity.sourceIp';
  if (typeof event.requestContext?.sourceIp === 'string' && event.requestContext.sourceIp) return 'requestContext.sourceIp';
  if (typeof event.clientIP === 'string' && event.clientIP) return 'clientIP';
  // On the CloudBase HTTP access path, the gateway overwrites X-Real-IP.
  // Require platform request markers and a single valid IP before using it.
  if (event.requestContext?.envId && event.requestContext?.requestId && net.isIP(header(event.headers, 'x-real-ip'))) return 'cloudbase.x-real-ip';
  return 'unknown';
}
function visitorIp(event) {
  // Prefer platform fields; use X-Real-IP only for a recognized CloudBase HTTP event.
  const source = visitorIpSource(event);
  const sources = [
    ['requestContext.identity.sourceIp', event.requestContext?.identity?.sourceIp],
    ['requestContext.sourceIp', event.requestContext?.sourceIp],
    ['clientIP', event.clientIP],
    ['cloudbase.x-real-ip', header(event.headers, 'x-real-ip')],
  ];
  if (!loggedIpSource) { console.info('seo-audit IP field:', source); loggedIpSource = true; }
  return String(sources.find(([name]) => name === source)?.[1] || 'unknown');
}
function limited(ip, now = Date.now()) {
  for (const [key, bucket] of buckets) if (now - bucket.start >= 60_000) buckets.delete(key);
  let bucket = buckets.get(ip);
  if (!bucket) { bucket = { start: now, count: 0 }; buckets.set(ip, bucket); }
  bucket.count++;
  return bucket.count > MAX_PER_MINUTE;
}
function rawBody(event) {
  if (typeof event.body !== 'string') throw new Error('INVALID_BODY');
  // Check encoded length before allocating the decoded buffer.
  if (Buffer.byteLength(event.body) > MAX_BODY * 2) throw new Error('BODY_TOO_LARGE');
  const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : event.body;
  if (Buffer.byteLength(raw) > MAX_BODY) throw new Error('BODY_TOO_LARGE');
  return raw;
}
exports.main = async (event = {}) => {
  // CloudBase may pass the path relative to the access route. The gateway
  // binds this function only to /api/seo/audit, so validate the method here.
  if (String(event.httpMethod || '').toUpperCase() !== 'POST') return reply(405, { error: { code: 'method_not_allowed', message: '仅支持 POST 请求。' } });
  if (limited(visitorIp(event))) return reply(429, { error: { code: 'rate_limited', message: '请求过于频繁，请稍后再试。' } });
  let data;
  try { data = JSON.parse(rawBody(event)); }
  catch (error) {
    return reply(error.message === 'BODY_TOO_LARGE' ? 413 : 400, { error: {
      code: error.message === 'BODY_TOO_LARGE' ? 'body_too_large' : 'invalid_body',
      message: error.message === 'BODY_TOO_LARGE' ? '请求内容过大。' : '请求格式无效。',
    } });
  }
  if (!data || typeof data.url !== 'string' || data.url.length > 2048) return reply(400, { error: { code: 'invalid_url', message: '请提供有效的网站地址。' } });
  try { parsePublicUrl(data.url); }
  catch (error) { return reply(400, { error: { code: 'invalid_url', message: error.message } }); }
  if (active >= MAX_ACTIVE) return reply(503, { error: { code: 'busy', message: '当前检测请求较多，请稍后重试。' } });
  try {
    const cloud = require('wx-server-sdk');
    cloud.init({ env: cloud.DYNAMIC_CURRENT_ENV });
    if (await checkSharedLimit(cloud.database())) return reply(429, { error: { code: 'rate_limited', message: '当前检测请求较多，请稍后再试。' } });
  } catch (_) {
    return reply(503, { error: { code: 'limit_unavailable', message: '检测服务暂时不可用，请稍后重试。' } });
  }
  active++;
  const audit = runAudit(data.url);
  audit.then(() => { active--; }, () => { active--; });
  try {
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('检测时间较长，本次已停止等待，请稍后重试。')), 20_000);
      audit.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
    });
    return reply(200, result);
  } catch (error) {
    const invalid = /请输入|仅支持|公开网站|标准端口|不可公开|不可访问的地址|不是可公开访问/.test(error.message);
    return reply(invalid ? 400 : 502, { error: { code: invalid ? 'invalid_url' : 'audit_failed', message: error.message || '检测未完成。' } });
  }
};
exports.visitorIp = visitorIp;
