// 路径由若干跳组成:普通链路、VXLAN 封装(VTEP 入)、解封装(VTEP 出)。

export function link({ name, mtu, icmpFilter = false }) {
  if (!Number.isInteger(mtu) || mtu <= 0) {
    throw new RangeError(`link "${name}" 的 MTU 必须是正整数`);
  }
  return { type: 'link', name, mtu, icmpFilter };
}

export function encap({ name, overhead, outerVersion = 4, outerDf }) {
  if (!Number.isInteger(overhead) || overhead <= 0) {
    throw new RangeError(`encap "${name}" 的开销必须是正整数`);
  }
  if (outerVersion !== 4 && outerVersion !== 6) {
    throw new RangeError(`encap "${name}" 的 outerVersion 只能是 4 或 6`);
  }
  return { type: 'encap', name, overhead, outerVersion, outerDf };
}

export function decap({ name, overhead }) {
  if (!Number.isInteger(overhead) || overhead <= 0) {
    throw new RangeError(`decap "${name}" 的开销必须是正整数`);
  }
  return { type: 'decap', name, overhead };
}
