export const IPV4_HEADER_BYTES = 20;
export const IPV6_HEADER_BYTES = 40;

// RFC 4789 VXLAN(IPv4 UDP 承载)的典型开销:
// 外层 IPv4 20 + UDP 8 + VXLAN 8 + 内层以太网 14 = 50 字节
export const VXLAN_OVERHEAD_IPV4 = 50;
// IPv6 承载时外层头部为 40 字节
export const VXLAN_OVERHEAD_IPV6 = 70;

export const FRAGMENTATION_POLICY = Object.freeze({
  ALLOW: 'allow',
  DENY: 'deny',
});

export const DROP_REASON = Object.freeze({
  DF_SET: 'df-set-fragmentation-needed',
  IPV6_NO_ROUTER_FRAGMENTATION: 'ipv6-no-router-fragmentation',
  POLICY_DENY: 'fragmentation-disabled-by-policy',
});

export const OUTCOME = Object.freeze({
  DELIVERED: 'delivered',
  FRAGMENTED: 'fragmented',
  DROPPED: 'dropped',
  PMTUD_SUCCESS: 'pmtud-success',
  PMTUD_BLACKHOLE: 'pmtud-blackhole',
});
