# vxlan-mtu-fragmentation-validator
校验 VXLAN 封装后的 MTU、分片和 PMTUD 行为

> **不发送真实探测包**:本项目是纯离线模型,所有"转发""丢弃""ICMP
> 回包"都在内存中对路径拓扑做确定性推演,不创建 socket、不发任何网络流量。
> 用于在变更 underlay MTU / 隧道开销配置前,预先验证各跳是否会丢包。

## 背景

VXLAN 在原始报文外叠加约 50 字节开销(外层 IPv4 20 + UDP 8 + VXLAN 8 +
内层以太网 14;IPv6 承载时约 70 字节)。当 underlay MTU 与隧道开销、
PMTUD 配置不一致时,小包能通过、封装后的大包被静默丢弃,现场表现为
随机超时。本工具逐跳推演报文能否转发,并明确区分以下情形:

- 允许分片(IPv4 DF=0 且策略允许,按 8 字节对齐切分)
- 禁止分片后丢弃(DF=1,或策略禁用分片)
- IPv6 超 MTU(路由器永不分片,只能回 ICMPv6 PTB)
- PMTUD 黑洞(反向路径过滤 ICMP,发送方收不到 PTB)
- PMTUD 成功(PTB 送达,收缩后重传并写入 MTU 缓存)
- 过期缓存(陈旧 PMTU 条目被剔除,报文不钳制,重新学习)

## 用法

```js
import { createPacket } from './src/packet.js';
import { link, encap, decap } from './src/hops.js';
import { MtuCache } from './src/mtu-cache.js';
import { validatePath } from './src/validator.js';

const packet = createPacket({ size: 1500, ipVersion: 4, df: true });
const path = [
  link({ name: 'access', mtu: 1500 }),
  encap({ name: 'vtep-1', overhead: 50, outerVersion: 4, outerDf: true }),
  link({ name: 'underlay', mtu: 1500 }),
  decap({ name: 'vtep-2', overhead: 50 }),
];

const result = validatePath({
  packet,
  path,
  mtuCache: new MtuCache({ ttlMs: 600_000 }),
  now: 0,
});
// result.outcome: 'delivered' | 'fragmented' | 'dropped' |
//                 'pmtud-success' | 'pmtud-blackhole'
// result.trace:   每跳记录 { action, size, encapDepth, encapsulated, reason? }
// result.events:  pmtu-clamp / stale-cache / pmtud-update / icmp-filtered
```

## 模型说明

- **跳的类型**:`link`(带 MTU 的链路,可标记 `icmpFilter` 过滤回程
  ICMP)、`encap`(VTEP 封装,叠加开销并切换外层 IP 版本/DF)、
  `decap`(解封装,还原上一层)。支持多层封装嵌套。
- **分片**:仅 IPv4 且 DF=0 且策略为 `allow` 时在路由器侧分片;IPv6
  一律由源站负责,路由器直接丢弃并回 PTB。分片后的后续跳按最大分片
  尺寸继续推演(简化模型)。
- **PMTUD**:丢弃点生成 PTB(IPv4: ICMP fragmentation-needed;IPv6:
  ICMPv6 packet-too-big),沿反向路径回传;任一跳 `icmpFilter` 即判定
  黑洞。PTB 送达后按"丢弃点超出字节数"收缩发送方包长(自动含封装
  开销),重试直至通过或 PMTU 不再收敛。
- **MTU 缓存**:按目的地缓存发送方可用包长,带 TTL;过期条目读取时
  剔除并产生 `stale-cache` 事件。

## 测试

```sh
npm test   # node --test,需要 Node.js >= 24.16.0
```

覆盖:IPv4 DF 丢弃/分片/策略禁止、IPv6 PTB、jumbo frame(9000 MTU)、
多层 VXLAN 嵌套、PMTUD 成功与黑洞、ICMP 过滤、过期缓存。
