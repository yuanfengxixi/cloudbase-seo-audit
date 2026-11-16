'use strict';
const cloud = require('wx-server-sdk');
cloud.init({ env: cloud.DYNAMIC_CURRENT_ENV });

exports.main = async () => {
  const db = cloud.database();
  const cutoff = Date.now();
  const command = db.command;
  let removed = 0;
  // Bounded work per scheduled run; the global limiter creates at most one
  // document per minute, so 2,000 records cover more than a full day.
  for (let batch = 0; batch < 20; batch++) {
    const result = await db.collection('seo_audit_rate')
      .where({ expiresAt: command.lt(cutoff) }).limit(100).remove();
    const count = Number(result?.stats?.removed || result?.deleted || 0);
    removed += count;
    if (count < 100) break;
  }
  return { removed };
};
