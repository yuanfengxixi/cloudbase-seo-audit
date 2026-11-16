'use strict';
const { createServer } = require('./server.cjs');
const port = Number(process.env.PORT || 8081);
const host = process.env.HOST || '127.0.0.1';
const server = createServer();
server.listen(port, host, () => process.stdout.write(`SEO audit API listening on http://${host}:${port}\n`));
server.on('error', (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
