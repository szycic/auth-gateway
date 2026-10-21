/**
 * Security Audit Logger for Auth Gateway.
 * Emits structured security events to stdout for monitoring, SIEM, and fail2ban ingestion.
 */

function formatValue(val) {
  if (typeof val === 'string') {
    if (val.includes(' ') || val.includes('"') || val.includes('=')) {
      return JSON.stringify(val);
    }
    return val;
  }
  return String(val);
}

function auditLog(event, details = {}) {
  const parts = Object.entries(details)
    .filter(([_, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${formatValue(v)}`);
  const detailsStr = parts.length > 0 ? ' ' + parts.join(' ') : '';
  console.log(`[AUTH_AUDIT] [${event}]${detailsStr}`);
}

module.exports = {
  auditLog,
};
