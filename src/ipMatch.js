const ipaddr = require('ipaddr.js');

/**
 * Normalizes a raw connection/header IP (handles IPv4-mapped IPv6 like ::ffff:10.0.0.5)
 */
function normalize(ip) {
  if (!ip) return null;
  let clean = ip.trim();
  if (clean.startsWith('::ffff:')) clean = clean.substring(7);
  try {
    return ipaddr.parse(clean);
  } catch (e) {
    return null;
  }
}

/**
 * Returns true if `ip` falls inside any of the given CIDR ranges or exact-match allow list.
 */
function isOrgTraffic(ip, orgNetworks, orgAllowList) {
  const parsed = normalize(ip);
  if (!parsed) return false;

  if (orgAllowList && orgAllowList.includes(ip)) return true;

  for (const cidr of orgNetworks || []) {
    try {
      const [rangeAddr, prefix] = ipaddr.parseCIDR(cidr);
      if (parsed.kind() !== rangeAddr.kind()) continue;
      if (parsed.match([rangeAddr, prefix])) return true;
    } catch (e) {
      // skip malformed CIDR entries rather than crashing the gateway
      continue;
    }
  }
  return false;
}

/**
 * Extracts the "real" client IP from an Express request, respecting
 * config.trustProxyHeaders so spoofed X-Forwarded-For can't be used
 * to impersonate org traffic unless the operator explicitly trusts it.
 *
 * When traffic arrives via Cloudflare (tunnel or proxy), Cloudflare sets
 * CF-Connecting-IP to the real visitor IP - this is checked first since
 * it's more reliable than X-Forwarded-For (which can list multiple hops).
 */
function getClientIp(req, trustProxyHeaders) {
  if (trustProxyHeaders) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return cfIp.trim();

    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress;
}

module.exports = { isOrgTraffic, getClientIp, normalize };
