const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const db = require('../db');
const terminal = require('../terminal');

const AUTH_COOKIE = 'hp_admin';

function createAdminApp(config) {
  const app = express();
  app.disable('x-powered-by');
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', '..', 'views'));
  app.use(cookieParser(config.sessionSecret));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use('/static', express.static(path.join(__dirname, '..', '..', 'public', 'admin')));

  const isAuthed = (req) => req.signedCookies[AUTH_COOKIE] === 'ok';

  app.get('/login', (req, res) => {
    if (isAuthed(req)) return res.redirect('/welcome');
    res.render('login', {
      brand: config.honeypotBrand,
      tagline: config.honeypotTagline,
      error: req.query.e === '1'
    });
  });

  app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === config.adminUser && password === config.adminPassword) {
      res.cookie(AUTH_COOKIE, 'ok', {
        httpOnly: true,
        signed: true,
        maxAge: 1000 * 60 * 60 * 8 // 8 hours
      });
      return res.redirect('/welcome');
    }
    res.redirect('/login?e=1');
  });

  app.get('/logout', (req, res) => {
    res.clearCookie(AUTH_COOKIE);
    res.redirect('/login');
  });

  // Everything below requires a valid session
  app.use((req, res, next) => {
    if (!isAuthed(req)) return res.redirect('/login');
    next();
  });

  app.get('/welcome', (req, res) => {
    const stats = db.getStats();
    res.render('welcome', {
      brand: config.honeypotBrand,
      adminUser: config.adminUser,
      stats
    });
  });

  app.get('/terminal', (req, res) => {
    res.render('terminal', { brand: config.honeypotBrand, adminUser: config.adminUser });
  });

  app.post('/api/terminal', (req, res) => {
    const command = (req.body && req.body.command) || '';
    try {
      const result = terminal.executeCommand(command, config);
      res.json(result);
    } catch (e) {
      res.json({ output: 'internal error: ' + e.message, error: true });
    }
  });

  app.get('/', (req, res) => {
    const stats = db.getStats();
    const sessions = db.listSessions();
    res.render('traffic', {
      brand: config.honeypotBrand,
      stats,
      sessions,
      protection: {
        realSiteTarget: config.realSiteTarget,
        gatewayPort: config.gatewayPort,
        companyName: config.companyName,
        orgNetworks: config.orgNetworks
      }
    });
  });

  app.get('/unknown-traffic', (req, res) => {
    const sessions = db.listSessions().filter((s) => s.risk_score < 5);
    res.render('unknown_traffic', { brand: config.honeypotBrand, sessions });
  });

  app.get('/attackers', (req, res) => {
    const sessions = db.listSessions()
      .filter((s) => s.risk_score >= 5)
      .map((s) => ({ ...s, cred_count: db.getCredentialsForSession(s.id).length }));
    res.render('attackers', { brand: config.honeypotBrand, sessions });
  });

  app.get('/history', (req, res) => {
    const stats = db.getStats();
    const requestsPerDay = db.getRequestsPerDay(14);
    const aimDistribution = db.getAimDistribution(8);
    const riskBuckets = db.getRiskBuckets();
    res.render('history', {
      brand: config.honeypotBrand,
      stats,
      requestsPerDay,
      aimDistribution,
      riskBuckets
    });
  });

  app.get('/alert', (req, res) => {
    res.render('alert', { brand: config.honeypotBrand, alerts: db.listAlerts() });
  });

  app.post('/alert', (req, res) => {
    const message = (req.body && req.body.message || '').trim();
    if (message) db.addAlert(message, config.adminUser);
    res.redirect('/alert');
  });

  app.get('/sessions/:id', (req, res) => {
    const session = db.getSession(req.params.id);
    if (!session) return res.status(404).send('Session not found');
    const requests = db.getRequestsForSession(req.params.id);
    const credentials = db.getCredentialsForSession(req.params.id);
    res.render('session_detail', {
      brand: config.honeypotBrand,
      session,
      requests: requests.map((r) => ({ ...r, aims: JSON.parse(r.aims || '[]') })),
      credentials
    });
  });

  app.post('/reset', (req, res) => {
    db.resetAll();
    res.redirect('/');
  });

  return app;
}

module.exports = { createAdminApp };
