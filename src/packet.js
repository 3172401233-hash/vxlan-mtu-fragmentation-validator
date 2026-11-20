export function createPacket({ size, ipVersion = 4, df = false }) {
  if (!Number.isInteger(size) || size <= 0) {
    throw new RangeError('报文大小必须是正整数');
  }
  if (ipVersion !== 4 && ipVersion !== 6) {
    throw new RangeError('ipVersion 只能是 4 或 6');
  }
  if (ipVersion === 6 && df) {
    throw new RangeError('IPv6 没有 DF 标志(路由器永不分片)');
  }
  return { size, ipVersion, df: ipVersion === 4 ? Boolean(df) : false };
}
