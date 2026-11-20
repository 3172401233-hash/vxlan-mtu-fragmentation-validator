import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DROP_REASON, OUTCOME, VXLAN_OVERHEAD_IPV6 } from '../src/constants.js';
import { createPacket } from '../src/packet.js';
import { link, encap } from '../src/hops.js';
import { forwardOnce, validatePath } from '../src/validator.js';

test('IPv6 不允许带 DF 标志', () => {
  assert.throws(() => createPacket({ size: 100, ipVersion: 6, df: true }), RangeError);
});

test('IPv6 超 MTU 时路由器不分片,丢弃并回 ICMPv6 PTB', () => {
  const packet = createPacket({ size: 1500, ipVersion: 6 });
  const path = [
    encap({ name: 'vtep-v6', overhead: VXLAN_OVERHEAD_IPV6, outerVersion: 6 }),
    link({ name: 'underlay', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DROPPED);
  const drop = result.trace.at(-1);
  assert.equal(drop.reason, DROP_REASON.IPV6_NO_ROUTER_FRAGMENTATION);
  assert.equal(drop.ptb.kind, 'icmpv6-packet-too-big');
  assert.equal(drop.size, 1570);
});

test('IPv6 PMTUD:源站收缩后重传成功', () => {
  const packet = createPacket({ size: 1500, ipVersion: 6 });
  const path = [
    encap({ name: 'vtep-v6', overhead: VXLAN_OVERHEAD_IPV6, outerVersion: 6 }),
    link({ name: 'underlay', mtu: 1500 }),
  ];
  const result = validatePath({ packet, path });
  assert.equal(result.outcome, OUTCOME.PMTUD_SUCCESS);
  assert.equal(result.attempts.length, 2);
  // 收缩 1570 - 1500 = 70,重传 1430 + 70 = 1500 恰好通过
  assert.equal(result.attempts[1].trace.at(-1).size, 1500);
});
