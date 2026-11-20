// Lightweight, dependency-free heuristics that label what an incoming
// request is probably trying to do. This is intentionally simple pattern
// matching (not a full IDS) so the admin dashboard can show a human-readable
// "aim" per request without shipping a signature engine.

const RULES = [
  { label: 'Credential harvesting', test: (r) => /login|signin|sign-in|auth|wp-login/i.test(r.path) && r.method === 'POST' },
  { label: 'Password reset abuse', test: (r) => /forgot-password|verify-code/i.test(r.path) && r.method === 'POST' },
  { label: 'Admin panel probing', test: (r) => /admin|wp-admin|phpmyadmin|cpanel|manager\/html/i.test(r.path) },
  { label: 'Sensitive file access', test: (r) => /\.env|\.git|\.svn|config\.php|wp-config|id_rsa|\.ssh|backup\.(sql|zip|tar)/i.test(r.path) },
  { label: 'Path traversal attempt', test: (r) => /\.\.\/|\.\.%2f|%2e%2e/i.test(r.path + '?' + r.query) },
  { label: 'SQL injection attempt', test: (r) => /('|%27)|(\bor\b.*=.*)|union(\s|%20)+select|;--|sleep\(\d+\)/i.test(r.query + ' ' + JSON.stringify(r.body || {})) },
  { label: 'XSS attempt', test: (r) => /<script|onerror=|onload=|javascript:/i.test(r.query + ' ' + JSON.stringify(r.body || {})) },
  { label: 'Command injection attempt', test: (r) => /(;|\|\||&&)\s*(cat|ls|whoami|uname|wget|curl)\b/i.test(r.query + ' ' + JSON.stringify(r.body || {})) },
  { label: 'Vulnerability/CMS scanning', test: (r) => /wp-content|xmlrpc\.php|readme\.html|CHANGELOG|shell\.php/i.test(r.path) },
  { label: 'API/endpoint enumeration', test: (r) => /^\/api\//i.test(r.path) },
  { label: 'Automated scanner/bot', test: (r) => /sqlmap|nikto|nmap|masscan|zgrab|nuclei|python-requests|curl\/|libwww/i.test(r.userAgent || '') }
];

function classify(request) {
  const matches = RULES.filter((rule) => {
    try {
      return rule.test(request);
    } catch (e) {
      return false;
    }
  }).map((r) => r.label);

  if (matches.length === 0) matches.push('Reconnaissance / browsing');
  return matches;
}

module.exports = { classify };
