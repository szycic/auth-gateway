const express = require('express');
const cookieParser = require('cookie-parser');
const routes = require('./routes');
const { renderStatusNoticeHtml } = require('./views/statusNoticeView');

const app = express();

app.set('trust proxy', 1);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mount all application routes
app.use(routes);

// Global 404 Not Found Handler
app.use((req, res) => {
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ error: 'Not Found', path: req.originalUrl });
  }
  return res.status(404).send(renderStatusNoticeHtml({
    title: '404 - Not Found',
    message: 'The requested page or endpoint does not exist.',
    actionUrl: '/',
    actionLabel: 'Return Home',
    type: 'error',
  }));
});

// Global 500 Uncaught Error Handler
app.use((err, req, res, next) => {
  console.error('[auth-gateway uncaught error]', err);
  if (res.headersSent) {
    return next(err);
  }
  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
  return res.status(500).send(renderStatusNoticeHtml({
    title: '500 - Server Error',
    message: 'An unexpected error occurred while processing your request. Please try again.',
    actionUrl: '/',
    actionLabel: 'Return Home',
    type: 'error',
  }));
});

module.exports = app;
