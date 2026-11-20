const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const crypto = require('crypto');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');
const UAParser = require('ua-parser-js');

const db = require('./db');
const { isOrgTraffic, getClientIp } = require('./ipMatch');
const { lookupIp } = require('./geoip');
const { classify } = require('./classify');

const SESSION_COOKIE = 'hp_sid';

function createGatewayApp(config) {
  const app = express();
  app.disable('x-powered-by');
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.use(morgan('tiny'));
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  const proxy = createProxyMiddleware({
    target: config.realSiteTarget,
    changeOrigin: true,
    logLevel: 'silent'
  });

  // --- Org vs. everyone-else gate -----------------------------------------
  app.use((req, res, next) => {
    const ip = getClientIp(req, config.trustProxyHeaders);
    req.clientIp = ip;
    req.isOrg = isOrgTraffic(ip, config.orgNetworks, config.orgAllowList);
    next();
  });

  app.use((req, res, next) => {
    if (req.isOrg) return proxy(req, res, next);
    next();
  });

  // --- Everything below only runs for non-org ("attacker") traffic -------
  app.use((req, res, next) => {
    let sid = req.cookies[SESSION_COOKIE];
    if (!sid) {
      sid = crypto.randomBytes(16).toString('hex');
      res.cookie(SESSION_COOKIE, sid, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 30 });
    }
    req.sessionId = sid;
    next();
  });

  app.use((req, res, next) => {
    if (req.path.startsWith('/honeypot/')) return next(); // static assets, don't log as "activity"
    logRequest(req, config);
    next();
  });

  app.use('/honeypot', express.static(path.join(__dirname, '..', 'public', 'honeypot')));

  app.post('/api/track', (req, res) => {
    const { fingerprintHash, geo } = req.body || {};
    if (geo) {
      db.updateBrowserGeo(req.sessionId, {
        lat: geo.lat,
        lon: geo.lon,
        accuracy: geo.accuracy,
        permission: geo.permission,
        fingerprintHash
      });
    }
    res.status(204).end();
  });

  app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    db.addCredentialAttempt(req.sessionId, username || '', password || '');
    // Always "fail" so the attacker keeps trying and generating more data.
    setTimeout(() => {
      res.redirect('/?e=1');
    }, 600);
  });

  app.get('/forgot-password', (req, res) => {
    res.render('forgot_password', { companyName: config.companyName });
  });

  app.post('/forgot-password', (req, res) => {
    const email = (req.body && req.body.email) || '';
    db.addCredentialAttempt(req.sessionId, email, '[password-reset-request]');
    setTimeout(() => {
      res.redirect('/verify-code?email=' + encodeURIComponent(email));
    }, 500);
  });

  app.get('/verify-code', (req, res) => {
    res.render('verify_code', { companyName: config.companyName, email: req.query.email || '' });
  });

  app.post('/verify-code', (req, res) => {
    const { email, code } = req.body || {};
    db.addCredentialAttempt(req.sessionId, email || '', '[reset-code] ' + (code || ''));
    setTimeout(() => {
      res.render('reset_expired', { companyName: config.companyName });
    }, 500);
  });

  // Catch-all: serve the decoy for any other path an attacker probes
  app.get('*', (req, res) => {
    res.render('honeypot', {
      siteTitleDecoy: config.siteTitleDecoy,
      companyName: config.companyName,
      year: new Date().getFullYear(),
      error: req.query.e === '1'
    });
  });

  app.post('*', (req, res) => {
    res.status(404).send('Not found');
  });

  return app;
}

function logRequest(req, config) {
  const ua = new UAParser(req.headers['user-agent']);
  const uaResult = ua.getResult();
  const geo = lookupIp(req.clientIp);

  db.upsertSession({
    id: req.sessionId,
    ip: req.clientIp,
    user_agent: req.headers['user-agent'] || '',
    browser: uaResult.browser.name || null,
    os: uaResult.os.name || null,
    device: uaResult.device.type || 'desktop',
    ip_country: geo ? geo.country : null,
    ip_region: geo ? geo.region : null,
    ip_city: geo ? geo.city : null,
    ip_lat: geo ? geo.lat : null,
    ip_lon: geo ? geo.lon : null
  });

  const requestInfo = {
    path: req.path,
    query: req.originalUrl.includes('?') ? req.originalUrl.split('?')[1] : '',
    method: req.method,
    body: req.body,
    userAgent: req.headers['user-agent'] || ''
  };
  const aims = classify(requestInfo);

  db.addRequest({
    session_id: req.sessionId,
    ts: new Date().toISOString(),
    method: req.method,
    path: req.path,
    query: requestInfo.query,
    body: JSON.stringify(req.body || {}),
    headers: JSON.stringify(req.headers || {}),
    aims: JSON.stringify(aims)
  });
}

module.exports = { createGatewayApp };
