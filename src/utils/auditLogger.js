const fs = require('fs');
const path = require('path');
const config = require('../config');

const MAX_IN_MEMORY = 5000;
const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 MB before rotation
const AUDIT_FILE = path.join(config.DATA_DIR, 'audit.jsonl');

const inMemoryLogs = [];

/**
 * Format primitive value for stdout log formatting.
 */
function formatValue(val) {
  if (typeof val === 'string') {
    if (val.includes(' ') || val.includes('"') || val.includes('=')) {
      return JSON.stringify(val);
    }
    return val;
  }
  if (typeof val === 'object' && val !== null) {
    try {
      return JSON.stringify(val);
    } catch (_) {
      return String(val);
    }
  }
  return String(val);
}

/**
 * Load existing logs from disk on startup into memory buffer.
 */
function loadExistingLogs() {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return;
    const content = fs.readFileSync(AUDIT_FILE, 'utf8');
    const lines = content.split('\n');
    
    // Tail up to MAX_IN_MEMORY lines
    const startIdx = Math.max(0, lines.length - MAX_IN_MEMORY - 1);
    for (let i = startIdx; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const parsed = JSON.parse(line);
        if (parsed && parsed.timestamp && parsed.event) {
          if (!parsed.id) {
            parsed.id = `log-${new Date(parsed.timestamp).getTime()}-${parsed.event}`;
          }
          const existing = inMemoryLogs.find(l => l.id === parsed.id);
          if (existing) {
            Object.assign(existing.details, parsed.details);
          } else {
            inMemoryLogs.push(parsed);
          }
        }
      } catch (_) {}
    }
    // Sort descending by timestamp (newest first)
    inMemoryLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  } catch (err) {
    console.error('[auth-gateway] Error reading existing audit logs from disk:', err.message);
  }
}

// Initial load
loadExistingLogs();

/**
 * Check if the audit file needs rotation.
 */
function checkRotation() {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return;
    const stat = fs.statSync(AUDIT_FILE);
    if (stat.size >= MAX_FILE_SIZE_BYTES) {
      const rotated = `${AUDIT_FILE}.1`;
      if (fs.existsSync(rotated)) {
        try { fs.unlinkSync(rotated); } catch (_) {}
      }
      fs.renameSync(AUDIT_FILE, rotated);
    }
  } catch (_) {}
}

/**
 * Emit and persist a security audit log event.
 * @param {string} event - Unique event key (e.g. 'LOGIN_SUCCESS', 'CSRF_BLOCKED')
 * @param {Record<string, any>} details - Associated metadata
 */
function auditLog(event, details = {}) {
  const timestamp = new Date().toISOString();
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const record = {
    id,
    timestamp,
    event,
    details: { ...details },
  };

  // Add to memory ring buffer (newest first)
  inMemoryLogs.unshift(record);
  if (inMemoryLogs.length > MAX_IN_MEMORY) {
    inMemoryLogs.pop();
  }

  // Format details for stdout console logging
  const parts = Object.entries(details)
    .filter(([_, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${formatValue(v)}`);
  const detailsStr = parts.length > 0 ? ' ' + parts.join(' ') : '';
  console.log(`[AUTH_AUDIT] [${event}]${detailsStr}`);

  // Asynchronously append to persistent JSONL log
  try {
    if (!fs.existsSync(config.DATA_DIR)) {
      fs.mkdirSync(config.DATA_DIR, { recursive: true });
    }
    checkRotation();
    fs.appendFile(AUDIT_FILE, JSON.stringify(record) + '\n', 'utf8', (err) => {
      if (err) {
        console.error('[auth-gateway] Failed to append to audit log file:', err.message);
      }
    });
  } catch (err) {
    console.error('[auth-gateway] Error in audit file write check:', err.message);
  }

  return record;
}

/**
 * Update attempt count on an existing log record when debouncing repeat events.
 */
function updateLogAttempts(record, attempts) {
  if (!record || !record.details) return;
  record.details.attempts = attempts;
  record.details.lastAttempt = new Date().toISOString();

  // Debounced append to file so updated attempts persist across restarts
  if (!record._flushTimer) {
    const timer = setTimeout(() => {
      record._flushTimer = null;
      try {
        fs.appendFile(AUDIT_FILE, JSON.stringify(record) + '\n', 'utf8', () => {});
      } catch (_) {}
    }, 3000);
    timer.unref();
    Object.defineProperty(record, '_flushTimer', {
      value: timer,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  }
}

/**
 * Event categories grouping for intuitive filtering.
 */
const EVENT_CATEGORIES = {
  auth: [
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'APPROVER_LOGIN_SUCCESS',
    'APPROVER_LOGIN_FAILED',
    'USER_FIDO_LOGIN_SUCCESS',
  ],
  revocation: [
    'SESSION_REVOKED',
    'APPROVER_SESSION_REVOKED',
    'ALL_SESSIONS_REVOKED',
    'USER_LOGOUT',
    'APPROVER_LOGOUT',
  ],
  security: [
    'CSRF_BLOCKED',
    'CSRF_LOGOUT_BLOCKED',
    'CROSS_SUBDOMAIN_BLOCKED',
    'LOCKOUT_TRIGGERED',
    'RATE_LIMIT_TRIGGERED',
    'SCANNER_PROBE_BLOCKED',
  ],
  approval: [
    'SESSION_APPROVED',
    'SESSION_REJECTED',
    'PAIR_CODE_VERIFIED',
  ],
  config: [
    'SESSION_PERMISSIONS_UPDATED',
    'DEVICE_RENAMED',
  ],
  access: [
    'SERVICE_ACCESS',
    'SERVICE_REDIRECT',
    'SERVICE_AUTH_REQUIRED',
  ],
};

/**
 * Determine the visual/severity class for an event name.
 */
function getEventClass(event = '') {
  const ev = String(event);
  if (ev.includes('SCANNER_') || ev.includes('RATE_LIMIT')) {
    return 'warning';
  }
  if (ev.includes('BLOCKED') || ev.includes('FAILED') || ev.includes('LOCKOUT')) {
    return 'danger';
  }
  if (ev.includes('LOGOUT') || ev.includes('REVOKED')) {
    return 'purple';
  }
  if (ev.includes('SUCCESS') || ev.includes('APPROVED')) {
    return 'success';
  }
  return 'info';
}

const CLASS_SEVERITY_RANK = {
  danger: 1,
  warning: 2,
  purple: 3,
  success: 4,
  info: 5,
};

function getEventClassRank(event) {
  const cls = getEventClass(event);
  return CLASS_SEVERITY_RANK[cls] || 99;
}

/**
 * Query and filter audit logs.
 */
function getAuditLogs({
  category = 'all',
  event = '',
  eventClass = '',
  class: cls = '',
  search = '',
  from = '',
  to = '',
  limit = 50,
  offset = 0,
  sort = 'time-desc',
} = {}) {
  const numLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  const numOffset = Math.max(parseInt(offset, 10) || 0, 0);

  const fromTime = from ? new Date(from).getTime() : 0;
  const toTime = to ? new Date(to).getTime() : Infinity;
  const searchLower = (search || '').trim().toLowerCase();

  // Support multiple classes (array or comma-separated string)
  const rawClass = eventClass || cls || '';
  const classList = (Array.isArray(rawClass) ? rawClass : String(rawClass).split(','))
    .map(c => c.trim().toLowerCase())
    .filter(c => c && c !== 'all');
  const allowedClasses = classList.length > 0 ? new Set(classList) : null;

  // Support multiple events (array or comma-separated string)
  const eventList = (Array.isArray(event) ? event : String(event || '').split(','))
    .map(e => e.trim())
    .filter(e => e && e !== 'all');
  const allowedSpecificEvents = eventList.length > 0 ? new Set(eventList) : null;

  const allowedEvents = category && category !== 'all' && EVENT_CATEGORIES[category]
    ? new Set(EVENT_CATEGORIES[category])
    : null;

  const filtered = inMemoryLogs.filter((entry) => {
    // 1. Event / Category / Class filter
    if (allowedSpecificEvents && !allowedSpecificEvents.has(entry.event)) return false;
    if (allowedEvents && !allowedEvents.has(entry.event)) return false;
    if (allowedClasses && !allowedClasses.has(getEventClass(entry.event))) return false;

    // 2. Timestamp range
    const entryTime = new Date(entry.timestamp).getTime();
    if (fromTime && entryTime < fromTime) return false;
    if (toTime && entryTime > toTime) return false;

    // 3. Search query
    if (searchLower) {
      if (entry.event.toLowerCase().includes(searchLower)) return true;
      if (entry.id.toLowerCase().includes(searchLower)) return true;
      
      const d = entry.details || {};
      for (const val of Object.values(d)) {
        if (val !== undefined && val !== null && String(val).toLowerCase().includes(searchLower)) {
          return true;
        }
      }
      return false;
    }

    return true;
  });

  // 4. Sorting
  if (sort === 'time-asc') {
    filtered.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  } else if (sort === 'class-desc') {
    filtered.sort((a, b) => {
      const diff = getEventClassRank(a.event) - getEventClassRank(b.event);
      if (diff !== 0) return diff;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
  } else if (sort === 'class-asc') {
    filtered.sort((a, b) => {
      const diff = getEventClassRank(b.event) - getEventClassRank(a.event);
      if (diff !== 0) return diff;
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
  } else {
    // Default: time-desc
    filtered.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  const total = inMemoryLogs.length;
  const filteredCount = filtered.length;
  const paged = filtered.slice(numOffset, numOffset + numLimit);

  return {
    logs: paged,
    total,
    filteredCount,
    eventTypes: getUniqueEvents(),
    limit: numLimit,
    offset: numOffset,
  };
}

/**
 * Retrieve a sorted list of unique event types currently present in the log buffer.
 */
function getUniqueEvents() {
  const events = new Set();
  for (const entry of inMemoryLogs) {
    if (entry && entry.event) {
      events.add(entry.event);
    }
  }
  return Array.from(events).sort();
}

/**
 * Calculate statistical summary for dashboard cards over the last 24 hours.
 */
function getAuditStats() {
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  let total24h = 0;
  let logins24h = 0;
  let securityAlerts24h = 0;
  let warnings24h = 0;
  const uniqueIps = new Set();

  for (const entry of inMemoryLogs) {
    const t = new Date(entry.timestamp).getTime();
    if (t < oneDayAgo) continue;

    total24h++;
    if (entry.details && entry.details.ip) {
      uniqueIps.add(entry.details.ip);
    }

    const evClass = getEventClass(entry.event);
    if (evClass === 'danger') {
      securityAlerts24h++;
    } else if (evClass === 'warning') {
      warnings24h++;
    } else if (evClass === 'success') {
      logins24h++;
    }
  }

  return {
    totalEvents: inMemoryLogs.length,
    total24h,
    logins24h,
    securityAlerts24h,
    warnings24h,
    lockouts24h: warnings24h,
    uniqueIps24h: uniqueIps.size,
  };
}

/**
 * Escape a single cell value for semicolon-delimited CSV.
 * Properly wraps in double quotes and escapes internal quotes with "".
 */
function escapeCsvCell(val) {
  if (val === null || val === undefined) return '""';
  const str = String(val);
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Format audit logs as semicolon-delimited CSV.
 */
function exportToCsv(logs) {
  const headers = ['Timestamp', 'Event', 'IP', 'Device', 'UUID', 'Service', 'Path', 'Details'];
  const rows = [headers.map(escapeCsvCell).join(';')];

  for (const log of logs) {
    const d = log.details || {};
    const ip = d.ip || d.clientIp || d.approverIp || d.revokedByIp || d.deviceIp || d.desktopIp || '';
    const device = d.friendlyDevice || d.device || d.targetDevice || d.approverDevice || '';
    const uuid = d.sessionId || d.uuid || '';
    const service = d.service || d.targetDomain || '';
    const path = d.path || '';

    const remainingDetails = { ...d };
    delete remainingDetails.ip;
    delete remainingDetails.clientIp;
    delete remainingDetails.approverIp;
    delete remainingDetails.friendlyDevice;
    delete remainingDetails.device;
    delete remainingDetails.targetDevice;
    delete remainingDetails.approverDevice;
    delete remainingDetails.sessionId;
    delete remainingDetails.uuid;
    delete remainingDetails.service;
    delete remainingDetails.targetDomain;
    delete remainingDetails.path;

    const detailsStr = Object.keys(remainingDetails).length > 0 ? JSON.stringify(remainingDetails) : '';

    const row = [
      escapeCsvCell(log.timestamp),
      escapeCsvCell(log.event),
      escapeCsvCell(ip),
      escapeCsvCell(device),
      escapeCsvCell(uuid),
      escapeCsvCell(service),
      escapeCsvCell(path),
      escapeCsvCell(detailsStr),
    ];
    rows.push(row.join(';'));
  }

  // Prepend UTF-8 BOM so Excel automatically recognizes UTF-8 encoding
  return '\uFEFF' + rows.join('\r\n');
}

module.exports = {
  auditLog,
  updateLogAttempts,
  getAuditLogs,
  getAuditStats,
  getUniqueEvents,
  getEventClass,
  getEventClassRank,
  exportToCsv,
  EVENT_CATEGORIES,
};
