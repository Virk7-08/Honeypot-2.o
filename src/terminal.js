const db = require('./db');

function parseArgs(str) {
  const args = [];
  const regex = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = regex.exec(str)) !== null) {
    args.push(m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]));
  }
  return args;
}

function pad(str, len) {
  str = String(str);
  return str.length >= len ? str : str + ' '.repeat(len - str.length);
}

function asciiTable(headers, rows) {
  if (rows.length === 0) {
    return '(no rows)';
  }
  const widths = headers.map((h, i) =>
    Math.max(String(h).length, ...rows.map((r) => String(r[i] == null ? '' : r[i]).length))
  );
  const sep = '+' + widths.map((w) => '-'.repeat(w + 2)).join('+') + '+';
  const headerLine = '| ' + headers.map((h, i) => pad(h, widths[i])).join(' | ') + ' |';
  const dataLines = rows.map(
    (r) => '| ' + r.map((c, i) => pad(c == null ? '' : c, widths[i])).join(' | ') + ' |'
  );
  return [sep, headerLine, sep, ...dataLines, sep].join('\n');
}

const HELP_TEXT = [
  'Available commands:',
  '',
  '  help                     show this help',
  '  traffic [n]              list all traffic (default 15 rows)   [alias: ls, dir]',
  '  unknown [n]              list unknown/low-risk traffic',
  '  attackers [n]            list confirmed attacker sessions',
  '  session <id-prefix>      show full detail for one session      [alias: cat session]',
  '  history [days]           requests-per-day table (default 14)',
  '  paths                    most probed paths',
  '  countries                top source countries',
  '  types                    top attack-type classifications        [alias: aims]',
  '  stats                    quick totals',
  '  whoami                   current admin + honeypot brand',
  '  alert <message>          send an alert to the security log',
  '  alerts [n]               list previously sent alerts',
  '  reset --yes              wipe all captured data (irreversible)',
  '  clear                    clear the screen                       [alias: cls]'
].join('\n');

function truncId(id) { return id.slice(0, 10) + '…'; }

function cmdTraffic(list, n) {
  const rows = list.slice(0, n).map((s) => [
    truncId(s.id), s.ip, s.ip_country || '-', s.request_count, s.risk_score
  ]);
  return asciiTable(['SESSION', 'IP', 'CC', 'REQS', 'RISK'], rows);
}

function executeCommand(raw, config) {
  const args = parseArgs((raw || '').trim());
  const cmd = (args[0] || '').toLowerCase();

  if (!cmd) return { output: '' };

  switch (cmd) {
    case 'help':
    case '?':
      return { output: HELP_TEXT };

    case 'whoami':
      return { output: `${config.adminUser}@${config.honeypotBrand.toLowerCase().replace(/\s+/g, '-')}` };

    case 'stats': {
      const s = db.getStats();
      return {
        output: asciiTable(
          ['METRIC', 'VALUE'],
          [['sessions', s.totalSessions], ['requests', s.totalRequests], ['credentials', s.totalCreds]]
        )
      };
    }

    case 'traffic':
    case 'ls':
    case 'dir': {
      const n = parseInt(args[1], 10) || 15;
      return { output: cmdTraffic(db.listSessions(), n) };
    }

    case 'unknown': {
      const n = parseInt(args[1], 10) || 15;
      const list = db.listSessions().filter((s) => s.risk_score < 5);
      return { output: cmdTraffic(list, n) };
    }

    case 'attackers': {
      const n = parseInt(args[1], 10) || 15;
      const list = db.listSessions().filter((s) => s.risk_score >= 5);
      const rows = list.slice(0, n).map((s) => [
        truncId(s.id), s.ip, s.ip_country || '-',
        db.getCredentialsForSession(s.id).length, s.request_count, s.risk_score
      ]);
      return { output: asciiTable(['SESSION', 'IP', 'CC', 'CREDS', 'REQS', 'RISK'], rows) };
    }

    case 'session':
    case 'cat': {
      let prefix = args[1];
      if (cmd === 'cat' && args[1] === 'session') prefix = args[2];
      if (!prefix) return { output: 'usage: session <id-prefix>', error: true };
      const match = db.listSessions().find((s) => s.id.startsWith(prefix));
      if (!match) return { output: `no session matching "${prefix}"`, error: true };
      const s = db.getSession(match.id);
      const creds = db.getCredentialsForSession(s.id);
      const lines = [
        `session:    ${s.id}`,
        `ip:         ${s.ip}`,
        `location:   ${[s.ip_city, s.ip_region, s.ip_country].filter(Boolean).join(', ') || '-'}`,
        `browser:    ${[s.browser, s.os].filter(Boolean).join(' / ') || '-'}`,
        `first_seen: ${s.first_seen}`,
        `last_seen:  ${s.last_seen}`,
        `requests:   ${s.request_count}`,
        `risk:       ${s.risk_score}`,
        `geo(gps):   ${s.geo_permission === 'granted' ? `${s.browser_lat}, ${s.browser_lon}` : (s.geo_permission || 'not reported')}`,
        '',
        `credential attempts: ${creds.length}`
      ];
      if (creds.length) {
        lines.push(asciiTable(['USERNAME', 'PASSWORD'], creds.map((c) => [c.username, c.password])));
      }
      return { output: lines.join('\n') };
    }

    case 'history': {
      const days = parseInt(args[1], 10) || 14;
      const data = db.getRequestsPerDay(days);
      return { output: asciiTable(['DAY', 'REQUESTS'], data.map((d) => [d.day, d.count])) };
    }

    case 'paths': {
      const s = db.getStats();
      return { output: asciiTable(['PATH', 'HITS'], s.topPaths.map((p) => [p.path, p.count])) };
    }

    case 'countries': {
      const s = db.getStats();
      return { output: asciiTable(['COUNTRY', 'SESSIONS'], s.topCountries.map((c) => [c.country, c.count])) };
    }

    case 'types':
    case 'aims': {
      const dist = db.getAimDistribution(10);
      return { output: asciiTable(['ATTACK TYPE', 'COUNT'], dist.map((a) => [a.label, a.count])) };
    }

    case 'alert': {
      const message = args.slice(1).join(' ');
      if (!message) return { output: 'usage: alert <message>', error: true };
      db.addAlert(message, config.adminUser);
      return { output: `[OK] alert sent to security log: "${message}"` };
    }

    case 'alerts': {
      const n = parseInt(args[1], 10) || 10;
      const list = db.listAlerts().slice(0, n);
      return { output: asciiTable(['TIME', 'MESSAGE'], list.map((a) => [a.ts, a.message])) };
    }

    case 'reset': {
      if (args[1] !== '--yes') {
        return { output: 'this permanently deletes all captured data. re-run as: reset --yes', error: true };
      }
      db.resetAll();
      return { output: '[OK] all captured data wiped.' };
    }

    case 'clear':
    case 'cls':
      return { output: '', clear: true };

    default:
      return { output: `command not found: ${cmd}\ntype "help" for a list of commands.`, error: true };
  }
}

module.exports = { executeCommand, asciiTable };
