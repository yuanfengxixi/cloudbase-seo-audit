'use strict';

const COLLECTION = 'seo_audit_rate';
const LIMIT_PER_MINUTE = 60;

async function checkSharedLimit(db, now = Date.now()) {
  const minute = Math.floor(now / 60_000);
  const id = `minute-${minute}`;
  const collection = db.collection(COLLECTION);
  try {
    await collection.add({ data: { _id: id, count: 1, expiresAt: now + 2 * 60 * 60_000 } });
  } catch (error) {
    // A concurrent invocation may have created the bucket. Re-read before
    // incrementing; fail closed if this was a database outage instead.
    const existing = await collection.doc(id).get();
    if (!existing?.data?._id) throw error;
    await collection.doc(id).update({ data: { count: db.command.inc(1) } });
  }
  const result = await collection.doc(id).get();
  if (!Number.isSafeInteger(result?.data?.count)) throw new Error('共享限流计数不可用。');
  return result.data.count > LIMIT_PER_MINUTE;
}

module.exports = { checkSharedLimit, COLLECTION, LIMIT_PER_MINUTE };
