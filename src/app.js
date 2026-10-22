const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const config = require('./config');
const sessionService = require('./services/sessionService');
const routes = require('./routes');

const app = express();

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.locals.config = config;
app.locals.isSessionAllowedForService = sessionService.isSessionAllowedForService;
app.locals.assetVersion = Date.now().toString(36);

const { isAuthDomain } = require('./utils/originHelper');

app.use(cookieParser());
app.use((req, res, next) => {
  if (req.path.startsWith('/auth/') || req.path === '/login' || isAuthDomain(req)) {
    return express.json()(req, res, (err) => {
      if (err) return next(err);
      express.urlencoded({ extended: true })(req, res, next);
    });
  }
  next();
});

app.use(routes);

// 404 handler
app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ error: 'Not Found', path: req.originalUrl });
  }
  return res.status(404).render('statusNotice', {
    title: '404 - Not Found',
    message: 'The requested page or endpoint does not exist.',
    actionUrl: '/',
    actionLabel: 'Return Home',
    type: 'error',
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('[auth-gateway uncaught error]', err);
  if (res.headersSent) {
    return next(err);
  }
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
  return res.status(500).render('statusNotice', {
    title: '500 - Server Error',
    message: 'An unexpected error occurred while processing your request. Please try again.',
    actionUrl: '/',
    actionLabel: 'Return Home',
    type: 'error',
  });
});

module.exports = app;
