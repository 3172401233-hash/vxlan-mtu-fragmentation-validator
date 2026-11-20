import {
  DROP_REASON,
  FRAGMENTATION_POLICY,
  IPV4_HEADER_BYTES,
  OUTCOME,
} from './constants.js';

// IPv4 分片:载荷按 8 字节对齐切分,每片带 20 字节头部。
export function computeFragments(size, mtu) {
  const payload = size - IPV4_HEADER_BYTES;
  const perFragment = Math.floor((mtu - IPV4_HEADER_BYTES) / 8) * 8;
  if (perFragment <= 0) {
    throw new RangeError(`MTU ${mtu} 太小,无法承载 IPv4 分片`);
  }
  const fragments = [];
  let remaining = payload;
  while (remaining > perFragment) {
    fragments.push(IPV4_HEADER_BYTES + perFragment);
    remaining -= perFragment;
  }
  fragments.push(IPV4_HEADER_BYTES + remaining);
  return fragments;
}

function dropReasonFor(current, fragmentationPolicy) {
  if (current.ipVersion === 6) return DROP_REASON.IPV6_NO_ROUTER_FRAGMENTATION;
  if (current.df) return DROP_REASON.DF_SET;
  if (fragmentationPolicy === FRAGMENTATION_POLICY.DENY) return DROP_REASON.POLICY_DENY;
  return null;
}

function ptbFor(current, mtu) {
  return {
    kind: current.ipVersion === 6 ? 'icmpv6-packet-too-big' : 'icmp-fragmentation-needed',
    mtu,
  };
}

// 单次逐跳转发。返回 { outcome, trace, drop? }。
// trace 中每一跳记录:动作、线上包大小、封装深度与状态、丢弃原因。
export function forwardOnce(packet, hops, { fragmentationPolicy = FRAGMENTATION_POLICY.ALLOW } = {}) {
  const trace = [];
  let current = { size: packet.size, ipVersion: packet.ipVersion, df: packet.df };
  const encapStack = [];
  let fragmented = false;

  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    const base = {
      hop: i,
      name: hop.name,
      encapDepth: encapStack.length,
      encapsulated: encapStack.length > 0,
    };

    if (hop.type === 'encap') {
      encapStack.push(current);
      current = {
        size: current.size + hop.overhead,
        ipVersion: hop.outerVersion,
        df: hop.outerDf ?? current.df,
      };
      trace.push({
        ...base,
        action: 'encap',
        overhead: hop.overhead,
        outerVersion: hop.outerVersion,
        encapDepth: encapStack.length,
        encapsulated: true,
        size: current.size,
      });
      continue;
    }

    if (hop.type === 'decap') {
      if (encapStack.length === 0) {
        throw new Error(`decap "${hop.name}" 没有匹配的 encap 跳`);
      }
      current = encapStack.pop();
      trace.push({
        ...base,
        action: 'decap',
        overhead: hop.overhead,
        size: current.size,
        encapDepth: encapStack.length,
        encapsulated: encapStack.length > 0,
      });
      continue;
    }

    if (current.size <= hop.mtu) {
      trace.push({ ...base, action: 'forward', mtu: hop.mtu, size: current.size });
      continue;
    }

    const reason = dropReasonFor(current, fragmentationPolicy);
    if (reason === null) {
      const fragments = computeFragments(current.size, hop.mtu);
      fragmented = true;
      trace.push({
        ...base,
        action: 'fragment',
        mtu: hop.mtu,
        size: current.size,
        fragments,
      });
      // 后续跳看到的是最大分片(简化模型,见 README)。
      current = { ...current, size: Math.max(...fragments) };
      continue;
    }

    const ptb = ptbFor(current, hop.mtu);
    trace.push({
      ...base,
      action: 'drop',
      mtu: hop.mtu,
      size: current.size,
      reason,
      ptb,
    });
    return {
      outcome: OUTCOME.DROPPED,
      drop: { hopIndex: i, reason, mtu: hop.mtu, size: current.size, ptb },
      trace,
    };
  }

  return { outcome: fragmented ? OUTCOME.FRAGMENTED : OUTCOME.DELIVERED, trace };
}

// PTB 需要沿反向路径回到发送方;任一跳过滤 ICMP 即形成黑洞。
function findIcmpFilter(hops, dropHopIndex) {
  for (let i = dropHopIndex - 1; i >= 0; i--) {
    if (hops[i].icmpFilter) return hops[i];
  }
  return null;
}

const MAX_PMTUD_ATTEMPTS = 10;

// 完整校验:MTU 缓存 -> 逐跳转发 -> 丢弃时按 PMTUD 学习并重试。
export function validatePath({
  packet,
  path,
  fragmentationPolicy = FRAGMENTATION_POLICY.ALLOW,
  pmtud = true,
  mtuCache = null,
  cacheKey = 'default',
  now = 0,
}) {
  const events = [];
  let effective = { ...packet };

  if (mtuCache) {
    const cached = mtuCache.get(cacheKey, now);
    if (cached.status === 'hit' && effective.size > cached.entry.mtu) {
      events.push({ type: 'pmtu-clamp', mtu: cached.entry.mtu });
      effective = { ...effective, size: cached.entry.mtu };
    } else if (cached.status === 'stale') {
      events.push({ type: 'stale-cache', expiredEntry: cached.entry });
    }
  }

  const attempts = [];
  let learnedMtu = null;

  for (let round = 0; round < MAX_PMTUD_ATTEMPTS; round++) {
    const attempt = forwardOnce(effective, path, { fragmentationPolicy });
    attempts.push(attempt);

    if (attempt.outcome !== OUTCOME.DROPPED) {
      const success = learnedMtu !== null || events.some((e) => e.type === 'pmtud-update');
      return {
        outcome: success ? OUTCOME.PMTUD_SUCCESS : attempt.outcome,
        events,
        attempts,
        trace: attempt.trace,
      };
    }

    if (!pmtud) {
      return { outcome: OUTCOME.DROPPED, events, attempts, trace: attempt.trace };
    }

    const filterHop = findIcmpFilter(path, attempt.drop.hopIndex);
    if (filterHop) {
      events.push({ type: 'icmp-filtered', hop: filterHop.name });
      return { outcome: OUTCOME.PMTUD_BLACKHOLE, events, attempts, trace: attempt.trace };
    }

    const { mtu, size } = attempt.drop;
    if (learnedMtu !== null && mtu >= learnedMtu) {
      // PMTU 没有进一步收敛,放弃以避免死循环。
      return { outcome: OUTCOME.DROPPED, events, attempts, trace: attempt.trace };
    }
    learnedMtu = mtu;
    // 发送方按 PTB 收缩:扣掉丢弃点超出的字节(含已叠加的封装开销)。
    const shrink = size - mtu;
    effective = { ...effective, size: effective.size - shrink };
    events.push({ type: 'pmtud-update', mtu, senderMtu: effective.size, reason: attempt.drop.reason });
    // 缓存存发送方可用包大小(已扣除封装开销),命中时可直接钳制。
    if (mtuCache) mtuCache.set(cacheKey, effective.size, now);
  }

  return { outcome: OUTCOME.DROPPED, events, attempts, trace: attempts.at(-1).trace };
}
