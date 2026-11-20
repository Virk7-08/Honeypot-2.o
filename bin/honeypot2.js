#!/usr/bin/env node

const { Command } = require('commander');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');

const { loadConfig } = require('../src/config');
const db = require('../src/db');
const { createGatewayApp } = require('../src/server');
const { createAdminApp } = require('../src/routes/admin');

const program = new Command();

program
  .name('honeypot2')
  .description('Honeypot 2.O by Virk7 - gateway + honeypot + admin dashboard')
  .version('1.0.0');

async function interactiveSetup(targetPath) {
  let existing = {};
  if (fs.existsSync(targetPath)) {
    try { existing = JSON.parse(fs.readFileSync(targetPath, 'utf8')); } catch (e) { existing = {}; }
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q, def) => new Promise((res) => rl.question(`${q} [${def}]: `, (a) => res(a.trim() || def)));

  console.log(
    Object.keys(existing).length
      ? '\nCurrent config.json found — press Enter to keep a value, or type a new one to overwrite it.\n'
      : '\nNo config.json found — let\'s set one up.\n'
  );

  const realSiteTarget = await ask('Real website to protect (proxied for org traffic)', existing.realSiteTarget || 'http://localhost:3000');
  const gatewayPort = await ask('Public gateway port', existing.gatewayPort || '8080');
  const adminPort = await ask('Admin dashboard port', existing.adminPort || '8081');
  const orgNetworksRaw = await ask('Org CIDR ranges, comma separated', (existing.orgNetworks && existing.orgNetworks.join(',')) || '10.0.0.0/8,192.168.0.0/16');
  const companyName = await ask('Company name shown on the decoy login page', existing.companyName || 'Acme Corporation');
  const adminUser = await ask('Admin dashboard username', existing.adminUser || 'admin');
  const adminPassword = await ask('Admin dashboard password', existing.adminPassword || 'change-me-now');
  rl.close();

  const example = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.example.json'), 'utf8'));
  const config = {
    ...example,
    ...existing,
    realSiteTarget,
    gatewayPort: Number(gatewayPort),
    adminPort: Number(adminPort),
    orgNetworks: orgNetworksRaw.split(',').map((s) => s.trim()).filter(Boolean),
    companyName,
    adminUser,
    adminPassword,
    sessionSecret: existing.sessionSecret || crypto.randomBytes(24).toString('hex')
  };
  for (const key of Object.keys(config)) {
    if (key.endsWith('_comment')) delete config[key];
  }

  fs.writeFileSync(targetPath, JSON.stringify(config, null, 2));
  console.log(`\nSaved ${targetPath}\n`);
}

program
  .command('init')
  .description('Interactively (re)create a config.json in the current directory')
  .action(async () => {
    const target = path.resolve('./config.json');
    if (fs.existsSync(target)) {
      console.log(`config.json already exists at ${target}. Delete it first if you want to regenerate.`);
      process.exit(1);
    }
    await interactiveSetup(target);
    console.log('Run "honeypot2 start" to launch.');
  });

program
  .command('start')
  .description('Start the gateway and admin dashboard (always asks for setup info, pre-filled from the existing config.json if one exists, and overwrites it)')
  .option('-c, --config <path>', 'path to config.json', './config.json')
  .action(async (opts) => {
    const target = path.resolve(opts.config);

    await interactiveSetup(target);

    let config;
    try {
      config = loadConfig(opts.config);
    } catch (e) {
      console.error(e.message);
      process.exit(1);
    }

    db.init(config.dbPath);

    const gatewayApp = createGatewayApp(config);
    const adminApp = createAdminApp(config);

    gatewayApp.listen(config.gatewayPort, () => {
      banner(config);
      console.log(`  Gateway listening on :${config.gatewayPort}  (org traffic -> ${config.realSiteTarget})`);
    });

    adminApp.listen(config.adminPort, () => {
      console.log(`  Admin dashboard on   :${config.adminPort}  (login: ${config.adminUser})`);
      console.log(`  Data stored at       ${config.dbPath}\n`);
    });
  });

function banner(config) {
  console.log('');
  console.log('  ██╗  ██╗██████╗ ██████╗    ██████╗   ██████╗');
  console.log('  ██║  ██║██╔══██╗╚════██╗  ██╔═══██╗ ██╔═══██╗');
  console.log('  ███████║██████╔╝ █████╔╝  ██║██╗██║ ██║██╗██║');
  console.log('  ██╔══██║██╔═══╝ ██╔═══╝   ██║╚═╝██║ ██║╚═╝██║');
  console.log('  ██║  ██║██║     ███████╗  ╚██████╔╝ ╚██████╔╝');
  console.log('  ╚═╝  ╚═╝╚═╝     ╚══════╝   ╚═════╝    ╚═════╝');
  console.log(`  ${config.honeypotBrand}`);
  console.log('');
}

program.parse(process.argv);
