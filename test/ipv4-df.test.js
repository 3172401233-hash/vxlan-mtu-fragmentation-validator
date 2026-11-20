import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DROP_REASON, FRAGMENTATION_POLICY, OUTCOME, VXLAN_OVERHEAD_IPV4 } from '../src/constants.js';
import { createPacket } from '../src/packet.js';
import { link, encap, decap } from '../src/hops.js';
import { computeFragments, forwardOnce, validatePath } from '../src/validator.js';

test('IPv4 DF=1 超过 underlay MTU 时丢弃并给出 DF 原因', () => {
  const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vtep-1', overhead: VXLAN_OVERHEAD_IPV4, outerVersion: 4, outerDf: true }),
    link({ name: 'underlay-1500', mtu: 1500 }),
  ];
  const result = validatePath({ packet, path, pmtud: false });
  assert.equal(result.outcome, OUTCOME.DROPPED);
  const drop = result.trace.at(-1);
  assert.equal(drop.action, 'drop');
  assert.equal(drop.reason, DROP_REASON.DF_SET);
  assert.equal(drop.size, 1550);
  assert.equal(drop.ptb.kind, 'icmp-fragmentation-needed');
  assert.equal(drop.ptb.mtu, 1500);
  assert.equal(drop.encapsulated, true);
});

test('IPv4 DF=0 允许分片时按 8 字节对齐切分并继续转发', () => {
  const packet = createPacket({ size: 4000, ipVersion: 4, df: false });
  const path = [
    link({ name: 'wan', mtu: 1500 }),
    link({ name: 'lan', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.FRAGMENTED);
  const fragHop = result.trace[0];
  assert.equal(fragHop.action, 'fragment');
  assert.deepEqual(fragHop.fragments, [1500, 1500, 1040]);
  // 后续跳看到最大分片
  assert.equal(result.trace[1].size, 1500);
});

test('IPv4 DF=0 但策略禁止分片时丢弃', () => {
  const packet = createPacket({ size: 4000, ipVersion: 4, df: false });
  const path = [link({ name: 'wan', mtu: 1500 })];
  const result = forwardOnce(packet, path, {
    fragmentationPolicy: FRAGMENTATION_POLICY.DENY,
  });
  assert.equal(result.outcome, OUTCOME.DROPPED);
  assert.equal(result.drop.reason, DROP_REASON.POLICY_DENY);
});

test('computeFragments 载荷按 8 字节对齐', () => {
  // MTU 600:每片载荷 floor((600-20)/8)*8 = 576,1480 = 576 + 576 + 328
  assert.deepEqual(computeFragments(1500, 600), [596, 596, 348]);
  assert.throws(() => computeFragments(1500, 10), RangeError);
});

test('小包在标准 MTU 路径上直接通过', () => {
  const packet = createPacket({ size: 200, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vtep-1', overhead: VXLAN_OVERHEAD_IPV4 }),
    link({ name: 'underlay', mtu: 1500 }),
    decap({ name: 'vtep-2', overhead: VXLAN_OVERHEAD_IPV4 }),
    link({ name: 'overlay', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DELIVERED);
  assert.deepEqual(
    result.trace.map((t) => [t.action, t.size, t.encapDepth]),
    [
      ['encap', 250, 1],
      ['forward', 250, 1],
      ['decap', 200, 0],
      ['forward', 200, 0],
    ],
  );
});
