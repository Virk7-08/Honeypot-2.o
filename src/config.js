const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  gatewayPort: 8080,
  adminPort: 8081,
  realSiteTarget: 'http://localhost:3000',
  trustProxyHeaders: false,
  orgNetworks: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  orgAllowList: [],
  adminUser: 'admin',
  adminPassword: 'change-me-now',
  dbPath: './data/honeypot.db',
  honeypotBrand: "Virk7's Honeypot",
  honeypotTagline: 'A deception gateway that separates trusted org traffic from everyone else — capturing attacker behavior, intent and geolocation in one dashboard.',
  siteTitleDecoy: 'Employee Portal - Sign In',
  companyName: 'Acme Corporation',
  sessionSecret: 'change-this-session-secret'
};

function loadConfig(configPath) {
  const resolved = path.resolve(configPath || './config.json');

  if (!fs.existsSync(resolved)) {
    throw new Error(
      `Config file not found at ${resolved}.\n` +
      `Run "honeypot2 init" to create one, or copy config.example.json to config.json.`
    );
  }

  const raw = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const config = { ...DEFAULTS, ...raw };

  // Strip helper _comment keys if user copied them over
  for (const key of Object.keys(config)) {
    if (key.endsWith('_comment')) delete config[key];
  }

  if (!Array.isArray(config.orgNetworks)) {
    throw new Error('config.orgNetworks must be an array of CIDR strings');
  }

  config.dbPath = path.resolve(path.dirname(resolved), config.dbPath);
  const dbDir = path.dirname(config.dbPath);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

  return config;
}

module.exports = { loadConfig, DEFAULTS };
