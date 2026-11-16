'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { checkSharedLimit, LIMIT_PER_MINUTE } = require('./cloud-function/shared-limit.cjs');

test('shared minute bucket caps calls across independent invocations', async () => {
  const records = new Map();
  const db = {
    command: { inc: (n) => ({ increment: n }) },
    collection: () => ({
      add: async ({ data }) => { if (records.has(data._id)) throw new Error('duplicate'); records.set(data._id, { ...data }); },
      doc: (id) => ({
        get: async () => ({ data: records.get(id) }),
        update: async ({ data }) => { records.get(id).count += data.count.increment; },
      }),
    }),
  };
  for (let i = 0; i < LIMIT_PER_MINUTE; i++) assert.equal(await checkSharedLimit(db, 100_000), false);
  assert.equal(await checkSharedLimit(db, 100_000), true);
  assert.equal(await checkSharedLimit(db, 160_000), false);
});

test('shared limiter fails closed when its database is unavailable', async () => {
  const db = { collection: () => ({ add: async () => { throw new Error('database unavailable'); }, doc: () => ({ get: async () => ({ data: null }) }) }) };
  await assert.rejects(() => checkSharedLimit(db), /database unavailable/);
});
