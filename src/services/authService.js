const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');
const { auditLog } = require('../utils/auditLogger');

const PASSWORD_FILE = path.join(config.DATA_DIR, 'password.json');
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes lockout

const failedLoginAttempts = new Map(); // ip -> { count, lockedUntil, firstFailedAt }
const pairingCodes = new Map(); // 8-digit code -> loginSessionId
const exchangeCodes = new Map(); // exchangeCode -> { token, expiresAt }

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const key = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt}$${key.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  if (!password || !storedHash || typeof password !== 'string' || typeof storedHash !== 'string') {
    return false;
  }
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const salt = parts[1];
  const originalKeyHex = parts[2];
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const derivedKeyHex = derivedKey.toString('hex');

  const bufA = Buffer.from(originalKeyHex, 'hex');
  const bufB = Buffer.from(derivedKeyHex, 'hex');

  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function getApproverPasswordHash() {
  if (process.env.APPROVER_PASSWORD_HASH && process.env.APPROVER_PASSWORD_HASH.trim().length > 0) {
    return process.env.APPROVER_PASSWORD_HASH.trim();
  }
  try {
    if (fs.existsSync(PASSWORD_FILE)) {
      const raw = fs.readFileSync(PASSWORD_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && data.approverPasswordHash && typeof data.approverPasswordHash === 'string') {
        return data.approverPasswordHash.trim();
      }
    }
  } catch (err) {
    console.error('[auth-gateway] Error reading password.json:', err.message);
  }
  return null;
}

let currentPasswordHash = getApproverPasswordHash();
let onPasswordChangedCallback = null;

function setOnPasswordChanged(callback) {
  onPasswordChangedCallback = callback;
}

function syncPasswordChanges() {
  const latestHash = getApproverPasswordHash();
  if (latestHash !== currentPasswordHash) {
    auditLog('PASSWORD_CHANGED', { source: 'sync' });
    console.log('[auth-gateway] Detected approver password change.');
    currentPasswordHash = latestHash;
    if (typeof onPasswordChangedCallback === 'function') {
      onPasswordChangedCallback();
    }
  }
}

// Watch password.json / DATA_DIR for password updates
try {
  if (fs.existsSync(PASSWORD_FILE)) {
    fs.watchFile(PASSWORD_FILE, { interval: 1000 }, syncPasswordChanges);
  } else if (fs.existsSync(config.DATA_DIR)) {
    fs.watch(config.DATA_DIR, (eventType, filename) => {
      if (filename === 'password.json') {
        syncPasswordChanges();
      }
    });
  }
} catch (e) {
  setInterval(syncPasswordChanges, 3000).unref();
}

function getClientIp(req) {
  const rawXff = req && req.headers && req.headers['x-forwarded-for'];
  const firstXff = typeof rawXff === 'string' ? rawXff.split(',')[0].trim() : null;
  return (req && req.ip) || firstXff || (req && req.socket && req.socket.remoteAddress) || '127.0.0.1';
}

function checkLoginLockout(clientIp) {
  const now = Date.now();
  const attemptRecord = failedLoginAttempts.get(clientIp);
  if (attemptRecord && attemptRecord.lockedUntil && attemptRecord.lockedUntil > now) {
    const remainingMins = Math.ceil((attemptRecord.lockedUntil - now) / 60000);
    return { locked: true, remainingMins };
  }
  return { locked: false };
}

function recordFailedLogin(clientIp) {
  const now = Date.now();
  const record = failedLoginAttempts.get(clientIp) || { count: 0, firstFailedAt: now, lockedUntil: null };
  record.count += 1;
  if (record.count >= MAX_LOGIN_ATTEMPTS) {
    record.lockedUntil = now + LOGIN_LOCKOUT_MS;
    failedLoginAttempts.set(clientIp, record);
    auditLog('LOCKOUT_TRIGGERED', { ip: clientIp, durationMins: LOGIN_LOCKOUT_MS / 60000 });
    return { locked: true, remainingAttempts: 0 };
  }
  failedLoginAttempts.set(clientIp, record);
  return { locked: false, remainingAttempts: MAX_LOGIN_ATTEMPTS - record.count };
}

function clearFailedLogins(clientIp) {
  failedLoginAttempts.delete(clientIp);
}

// Cleanup stale rate limit records every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of failedLoginAttempts.entries()) {
    if (data.lockedUntil && data.lockedUntil < now) {
      failedLoginAttempts.delete(ip);
    } else if (now - data.firstFailedAt > LOGIN_LOCKOUT_MS * 2) {
      failedLoginAttempts.delete(ip);
    }
  }
}, 30 * 60 * 1000).unref();

function generatePairCode() {
  for (let i = 0; i < 10; i++) {
    const code = String(crypto.randomInt(10000000, 100000000));
    if (!pairingCodes.has(code)) {
      return code;
    }
  }
  return String(crypto.randomInt(10000000, 100000000));
}

function createExchangeCode(sessionToken, ttlMs = 60000) {
  const exchangeCode = crypto.randomBytes(32).toString('base64url');
  exchangeCodes.set(exchangeCode, {
    token: sessionToken,
    expiresAt: Date.now() + ttlMs,
  });
  return exchangeCode;
}

function consumeExchangeCode(code) {
  if (!code || typeof code !== 'string') return null;
  const item = exchangeCodes.get(code);
  exchangeCodes.delete(code);
  if (item && item.expiresAt > Date.now()) {
    return item.token;
  }
  return null;
}

// Cleanup expired exchange codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [code, item] of exchangeCodes.entries()) {
    if (item.expiresAt < now) {
      exchangeCodes.delete(code);
    }
  }
}, 5 * 60 * 1000).unref();

function isGatewayTokenValid(req) {
  if (!config.GATEWAY_TOKEN || typeof config.GATEWAY_TOKEN !== 'string' || !config.GATEWAY_TOKEN.trim()) {
    return false;
  }
  if (!req || !req.headers) return false;

  const rawHeaderToken = req.headers['x-gateway-token'] ||
    req.headers['x-auth-token'] ||
    (req.headers['authorization'] && req.headers['authorization'].startsWith('Bearer ')
      ? req.headers['authorization'].slice(7).trim()
      : null);

  if (!rawHeaderToken || typeof rawHeaderToken !== 'string') {
    return false;
  }

  const expected = Buffer.from(String(config.GATEWAY_TOKEN).trim());
  const received = Buffer.from(String(rawHeaderToken).trim());
  if (expected.length !== received.length) {
    return false;
  }
  return crypto.timingSafeEqual(expected, received);
}

module.exports = {
  hashPassword,
  verifyPassword,
  getApproverPasswordHash,
  setOnPasswordChanged,
  syncPasswordChanges,
  getClientIp,
  checkLoginLockout,
  recordFailedLogin,
  clearFailedLogins,
  pairingCodes,
  generatePairCode,
  createExchangeCode,
  consumeExchangeCode,
  isGatewayTokenValid,
  MAX_LOGIN_ATTEMPTS,
  LOGIN_LOCKOUT_MS,
};
