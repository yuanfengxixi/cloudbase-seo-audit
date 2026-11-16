# CloudBase SEO Audit

A small Node.js and Tencent CloudBase service for checking a public website's basic SEO hygiene. It inspects the home page, `robots.txt`, `sitemap.xml`, and up to two same-origin pages when the site's `robots.txt` permits it.

The audit reports page title, meta description, H1 count, canonical link, resource status/format, and sampled-page availability. It is a lightweight diagnostic, not a ranking prediction or a substitute for a full SEO review.

## Run locally

Requires Node.js 20 or newer.

```bash
npm test
npm run package
npm start
```

The local server listens on `127.0.0.1:8081` by default. Submit an audit request:

```bash
curl -X POST http://127.0.0.1:8081/api/seo/audit \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}'
```

Set `HOST` or `PORT` to change the local listener. The local server uses an in-memory rate limit; CloudBase uses a shared database-backed limit.

## Deploy to CloudBase

1. Run `npm run package`.
2. Upload `.build/seo-audit` and `.build/seo-audit-rate-cleanup` as two CloudBase Cloud Functions.
3. Bind the audit function to the HTTP path in `cloud-function/config.json` (`/api/seo/audit`).
4. Enable the cleanup function's timer trigger from `rate-cleanup/config.json` and allow it to remove expired documents from the `seo_audit_rate` collection.

The functions use `wx-server-sdk` and `cloud.DYNAMIC_CURRENT_ENV`; no environment IDs, app secrets, or client records are embedded in this repository.

## Safety and limits

- Accepts only public HTTP/HTTPS website URLs on standard web ports; URLs with embedded credentials are rejected.
- Resolves and pins public IP addresses, rejects private/reserved addresses, and revalidates every redirect to reduce SSRF and DNS-rebinding risk.
- Caps request and response sizes, redirect depth, per-request time, concurrent requests, and per-IP request rates.
- Honors conservative `robots.txt` behavior before sampling same-origin pages; it does not follow off-site links.
- Returns JSON with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

This project includes no customer records, API credentials, site content archives, or private SEO operation reports. It sends HTTP requests only to the public URL submitted by the caller.

## Tests

The built-in Node test suite covers URL validation and SSRF protections, redirect/DNS behavior, resource checks, request limits, shared CloudBase rate limiting, and function packaging. GitHub Actions runs the tests on Node.js 20 and 22.

## License

MIT. See [LICENSE](LICENSE).
