const geoip = require('geoip-lite');

/**
 * Best-effort IP-based geolocation (no external calls, offline DB).
 * This always runs, as a fallback/cross-check for the browser
 * permission-based geolocation captured via /api/track.
 */
function lookupIp(ip) {
  const clean = (ip || '').replace('::ffff:', '');
  const geo = geoip.lookup(clean);
  if (!geo) return null;
  return {
    country: geo.country || null,
    region: geo.region || null,
    city: geo.city || null,
    lat: geo.ll ? geo.ll[0] : null,
    lon: geo.ll ? geo.ll[1] : null,
    timezone: geo.timezone || null
  };
}

module.exports = { lookupIp };
