const express = require('express');
const sessionService = require('../services/sessionService');
const {
  getAuditLogs,
  getAuditStats,
  getUniqueEvents,
  exportToCsv,
} = require('../utils/auditLogger');
const { verifySameOrigin } = require('../utils/csrfHelper');

const router = express.Router();
router.use(verifySameOrigin);

// Authentication Guard: strictly requires Approver credentials
function requireApprover(req, res, next) {
  if (!sessionService.isApprover(req)) {
    return res.redirect('/auth/approver/login?returnTo=/auth/audit');
  }
  next();
}

/**
 * GET /auth/audit
 * Visual dashboard view for approvers.
 */
router.get('/audit', requireApprover, (req, res) => {
  const stats = getAuditStats();
  const initialData = getAuditLogs({ limit: 50, offset: 0 });

  return res.render('auditDashboard', {
    title: 'Audit Log',
    stats,
    initialData,
    eventTypes: initialData.eventTypes || getUniqueEvents(),
  });
});

/**
 * GET /auth/audit/api
 * JSON query endpoint for interactive filtering, search, pagination, and live polling.
 */
router.get('/audit/api', requireApprover, (req, res) => {
  const { category, event, search, from, to, limit, offset } = req.query;

  const result = getAuditLogs({
    category,
    event,
    search,
    from,
    to,
    limit,
    offset,
  });

  const stats = getAuditStats();

  return res.json({
    success: true,
    ...result,
    stats,
  });
});

/**
 * GET /auth/audit/export
 * Download audit records as JSON or CSV.
 */
router.get('/audit/export', requireApprover, (req, res) => {
  const { format = 'json', category, event, search, from, to } = req.query;

  // Retrieve up to 5000 matching records for export
  const { logs } = getAuditLogs({
    category,
    event,
    search,
    from,
    to,
    limit: 5000,
    offset: 0,
  });

  const dateStr = new Date().toISOString().slice(0, 10);

  if (format === 'csv') {
    const csvContent = exportToCsv(logs);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="auth-audit-${dateStr}.csv"`);
    return res.send(csvContent);
  }

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="auth-audit-${dateStr}.json"`);
  return res.send(JSON.stringify(logs, null, 2));
});

module.exports = router;

