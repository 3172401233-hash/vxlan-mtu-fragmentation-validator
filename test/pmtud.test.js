import { test } from 'node:test';
import assert from 'node:assert/strict';

import { OUTCOME, VXLAN_OVERHEAD_IPV4 } from '../src/constants.js';
import { createPacket } from '../src/packet.js';
import { link, encap } from '../src/hops.js';
import { MtuCache } from '../src/mtu-cache.js';
import { validatePath } from '../src/validator.js';

function vxlanPath({ icmpFilter = false } = {}) {
  return [
    link({ name: 'access', mtu: 1500, icmpFilter }),
    encap({ name: 'vtep-1', overhead: VXLAN_OVERHEAD_IPV4, outerDf: true }),
    link({ name: 'underlay', mtu: 1500 }),
  ];
}

test('PMTUD 成功:PTB 送达后收缩重传并写入缓存', () => {
  const cache = new MtuCache({ ttlMs: 1000 });
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const result = validatePath({ packet, path: vxlanPath(), mtuCache: cache, now: 0 });

  assert.equal(result.outcome, OUTCOME.PMTUD_SUCCESS);
  assert.equal(result.attempts.length, 2);
  assert.deepEqual(
    result.events.map((e) => e.type),
    ['pmtud-update'],
  );
  // 缓存存的是发送方可用大小:1500 - 50 = 1450
  const cached = cache.get('default', 1);
  assert.equal(cached.status, 'hit');
  assert.equal(cached.entry.mtu, 1450);
});

test('PMTUD 黑洞:反向路径过滤 ICMP,发送方永远收不到 PTB', () => {
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const result = validatePath({ packet, path: vxlanPath({ icmpFilter: true }) });

  assert.equal(result.outcome, OUTCOME.PMTUD_BLACKHOLE);
  assert.deepEqual(
    result.events.map((e) => e.type),
    ['icmp-filtered'],
  );
  assert.equal(result.events[0].hop, 'access');
  assert.equal(result.attempts.length, 1);
});

test('缓存命中:按缓存 PMTU 钳制后直接通过', () => {
  const cache = new MtuCache({ ttlMs: 1000 });
  cache.set('default', 1450, 0);
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const result = validatePath({ packet, path: vxlanPath(), mtuCache: cache, now: 10 });

  assert.equal(result.outcome, OUTCOME.DELIVERED);
  assert.deepEqual(
    result.events.map((e) => e.type),
    ['pmtu-clamp'],
  );
  assert.equal(result.attempts.length, 1);
});

test('过期缓存:条目被剔除,报文不钳制,重新走 PMTUD 学习', () => {
  const cache = new MtuCache({ ttlMs: 100 });
  cache.set('default', 1450, 0);
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const result = validatePath({ packet, path: vxlanPath(), mtuCache: cache, now: 200 });

  assert.equal(result.events[0].type, 'stale-cache');
  assert.equal(result.events[0].expiredEntry.mtu, 1450);
  // 陈旧缓存被忽略后首包再次被丢,随后重新学习成功
  assert.equal(result.outcome, OUTCOME.PMTUD_SUCCESS);
  assert.equal(result.attempts.length, 2);
});

test('关闭 PMTUD 时丢弃即终态', () => {
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const result = validatePath({ packet, path: vxlanPath(), pmtud: false });
  assert.equal(result.outcome, OUTCOME.DROPPED);
  assert.equal(result.attempts.length, 1);
});
