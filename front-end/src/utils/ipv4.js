/**
 * ============================================================================
 * IPv4 HELPERS
 * ----------------------------------------------------------------------------
 * Leaf module: requires nothing, so site-config.js and lane-wan-allocator.js can
 * both pull it without a cycle.
 *
 * Exists because the lane WAN transit pool stopped being a fixed /24 whose host
 * part was the last octet. Once the block can be a /22 (or wider), "the address
 * is base3 + '.' + octet" is no longer true and every candidate has to be walked
 * as a 32-bit integer instead.
 * ============================================================================
 */

/** Dotted quad → unsigned 32-bit. Throws on anything that is not one. */
function ipToInt(ip) {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) throw new Error(`Not an IPv4 address: '${ip}'`);
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) throw new Error(`Not an IPv4 address: '${ip}'`);
    const b = Number(p);
    if (b > 255) throw new Error(`Not an IPv4 address: '${ip}' (octet ${b} > 255)`);
    n = (n * 256) + b;
  }
  return n;
}

/** Unsigned 32-bit → dotted quad. Arithmetic, not bit ops: `>>>` is fine here but
 *  `<<` overflows into negatives at the top of the space and has bitten this
 *  codebase before. */
function intToIp(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xFFFFFFFF) {
    throw new Error(`Not a valid IPv4 integer: ${n}`);
  }
  return [
    Math.floor(n / 16777216) % 256,
    Math.floor(n / 65536) % 256,
    Math.floor(n / 256) % 256,
    n % 256,
  ].join('.');
}

/**
 * Parse `a.b.c.d/len` into its parts.
 *
 * The address given need NOT be the network address — '100.100.60.5/22' parses
 * to the 100.100.60.0/22 block — so an operator writing the gateway with a
 * prefix into `subnet` still gets the right block rather than a silent
 * off-by-one-boundary pool.
 *
 * firstHost/lastHost exclude network and broadcast for prefixes ≤ /30. For /31
 * and /32 those concepts do not apply and both ends are usable, which is why
 * callers that need a real pool validate the prefix themselves.
 */
function parseCidr(cidr) {
  const m = String(cidr).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) throw new Error(`Not a CIDR block: '${cidr}' (expected e.g. 100.100.60.0/22)`);
  const prefixLen = Number(m[2]);
  if (prefixLen > 32) throw new Error(`Not a CIDR block: '${cidr}' (prefix /${prefixLen} > /32)`);

  const addr = ipToInt(m[1]);
  // 2 ** (32 - len) rather than a shift: `1 << 32` is 1, not 2^32, in JS.
  const size = Math.pow(2, 32 - prefixLen);
  const network = addr - (addr % size);
  const broadcast = network + size - 1;

  return {
    network:   intToIp(network),
    broadcast: intToIp(broadcast),
    firstHost: intToIp(prefixLen >= 31 ? network : network + 1),
    lastHost:  intToIp(prefixLen >= 31 ? broadcast : broadcast - 1),
    prefixLen,
    size,
  };
}

/** Is `ip` inside `cidr`? */
function ipInCidr(ip, cidr) {
  const { network, size } = parseCidr(cidr);
  const n = ipToInt(network);
  const v = ipToInt(ip);
  return v >= n && v < n + size;
}

module.exports = { ipToInt, intToIp, parseCidr, ipInCidr };
