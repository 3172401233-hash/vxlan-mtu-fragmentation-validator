import { test } from 'node:test';
import assert from 'node:assert/strict';

import { OUTCOME, VXLAN_OVERHEAD_IPV4 } from '../src/constants.js';
import { createPacket } from '../src/packet.js';
import { link, encap, decap } from '../src/hops.js';
import { forwardOnce } from '../src/validator.js';

test('jumbo frame:9000 MTU underlay 承载 VXLAN 大报文', () => {
  const packet = createPacket({ size: 8950, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vtep-1', overhead: VXLAN_OVERHEAD_IPV4 }),
    link({ name: 'underlay-jumbo', mtu: 9000 }),
    decap({ name: 'vtep-2', overhead: VXLAN_OVERHEAD_IPV4 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DELIVERED);
  assert.equal(result.trace[1].size, 9000);
});

test('标准 1500 underlay 上 jumbo 报文被丢弃', () => {
  const packet = createPacket({ size: 8950, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vtep-1', overhead: VXLAN_OVERHEAD_IPV4, outerDf: true }),
    link({ name: 'underlay-1500', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DROPPED);
  assert.equal(result.trace.at(-1).size, 9000);
});

test('多层封装:开销逐层叠加,解封装逐层还原', () => {
  const packet = createPacket({ size: 1400, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vxlan-l1', overhead: 50 }),
    encap({ name: 'vxlan-l2', overhead: 50 }),
    link({ name: 'underlay', mtu: 1500 }),
    decap({ name: 'vxlan-l2-out', overhead: 50 }),
    decap({ name: 'vxlan-l1-out', overhead: 50 }),
    link({ name: 'overlay', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DELIVERED);
  assert.deepEqual(
    result.trace.map((t) => [t.action, t.size, t.encapDepth]),
    [
      ['encap', 1450, 1],
      ['encap', 1500, 2],
      ['forward', 1500, 2],
      ['decap', 1450, 1],
      ['decap', 1400, 0],
      ['forward', 1400, 0],
    ],
  );
  assert.equal(result.trace[2].encapsulated, true);
  assert.equal(result.trace[5].encapsulated, false);
});

test('多层封装叠加后超 MTU 时在最内层可定位丢弃点', () => {
  const packet = createPacket({ size: 1480, ipVersion: 4, df: true });
  const path = [
    encap({ name: 'vxlan-l1', overhead: 50, outerDf: true }),
    encap({ name: 'vxlan-l2', overhead: 50, outerDf: true }),
    link({ name: 'underlay', mtu: 1500 }),
  ];
  const result = forwardOnce(packet, path);
  assert.equal(result.outcome, OUTCOME.DROPPED);
  const drop = result.trace.at(-1);
  assert.equal(drop.size, 1580);
  assert.equal(drop.encapDepth, 2);
});

test('decap 没有匹配的 encap 时报错', () => {
  const packet = createPacket({ size: 100, ipVersion: 4 });
  assert.throws(() => forwardOnce(packet, [decap({ name: 'orphan', overhead: 50 })]), /没有匹配/);
});
