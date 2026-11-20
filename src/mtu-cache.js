// PMTUD 缓存:按目的地记录已学习的 PMTU,带过期时间。
// 过期条目会被视为"陈旧缓存"并在读取时剔除。
export class MtuCache {
  constructor({ ttlMs = 600_000 } = {}) {
    this.ttlMs = ttlMs;
    this.entries = new Map();
  }

  set(key, mtu, now) {
    this.entries.set(key, { mtu, learnedAt: now, expiresAt: now + this.ttlMs });
  }

  get(key, now) {
    const entry = this.entries.get(key);
    if (!entry) return { status: 'miss' };
    if (entry.expiresAt <= now) {
      this.entries.delete(key);
      return { status: 'stale', entry };
    }
    return { status: 'hit', entry };
  }
}
