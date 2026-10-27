const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const config = require('../config');
const { auditLog } = require('../utils/auditLogger');

const CREDENTIALS_FILE = path.join(config.DATA_DIR, 'webauthn-credentials.json');
const AUTH_METHOD_FILE = path.join(config.DATA_DIR, 'auth-method.json');

const enrollmentEvents = new EventEmitter();
const pendingEnrollmentTokens = new Map(); // token -> { token, createdAt, expiresAt, challenge, completed: boolean }
const activeAuthChallenges = new Map(); // challengeId -> { challenge, createdAt, expiresAt }

let inMemoryCredentials = [];

function loadCredentials() {
  try {
    if (fs.existsSync(CREDENTIALS_FILE)) {
      const raw = fs.readFileSync(CREDENTIALS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data)) {
        inMemoryCredentials = data;
        return;
      }
    }
  } catch (err) {
    console.error('[auth-gateway] Error reading webauthn-credentials.json:', err.message);
  }
  inMemoryCredentials = [];
}

function saveCredentials() {
  try {
    if (!fs.existsSync(config.DATA_DIR)) {
      fs.mkdirSync(config.DATA_DIR, { recursive: true });
    }
    const tmp = `${CREDENTIALS_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(inMemoryCredentials, null, 2), 'utf8');
    fs.renameSync(tmp, CREDENTIALS_FILE);
  } catch (err) {
    console.error('[auth-gateway] Error saving webauthn-credentials.json:', err.message);
  }
}

loadCredentials();

function getActiveAuthMethod() {
  try {
    if (fs.existsSync(AUTH_METHOD_FILE)) {
      const raw = fs.readFileSync(AUTH_METHOD_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (data && (data.method === 'fido' || data.method === 'password')) {
        // Safe fallback: if set to 'fido' but there are no credentials registered, fall back to password
        if (data.method === 'fido' && inMemoryCredentials.length === 0) {
          return 'password';
        }
        return data.method;
      }
    }
  } catch (err) {
    console.error('[auth-gateway] Error reading auth-method.json:', err.message);
  }
  return 'password';
}

function setActiveAuthMethod(method) {
  if (method !== 'fido' && method !== 'password') {
    throw new Error(`Invalid auth method: ${method}`);
  }
  if (!fs.existsSync(config.DATA_DIR)) {
    fs.mkdirSync(config.DATA_DIR, { recursive: true });
  }
  const payload = {
    method,
    updatedAt: new Date().toISOString(),
  };
  const tmp = `${AUTH_METHOD_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmp, AUTH_METHOD_FILE);
  auditLog('AUTH_METHOD_CHANGED', { method });
  console.log(`[auth-gateway] Approver login method switched to: ${method}`);
  return payload;
}

function getRPID(req) {
  if (config.session && config.session.cookieDomain) {
    const cleaned = config.session.cookieDomain.replace(/^\./, '').split(':')[0].trim().toLowerCase();
    if (cleaned) return cleaned;
  }
  try {
    const parsed = new URL(config.server.baseUrl);
    return parsed.hostname.toLowerCase();
  } catch (_) {}

  if (req && req.headers && req.headers.host) {
    return req.headers.host.split(':')[0].toLowerCase();
  }
  return 'localhost';
}

function getExpectedOrigins(req) {
  const origins = new Set();
  if (config.server && config.server.baseUrl) {
    try {
      origins.add(new URL(config.server.baseUrl).origin);
    } catch (_) {}
  }

  if (req && req.headers) {
    if (req.headers.origin) origins.add(req.headers.origin);
    if (req.headers.host) {
      origins.add(`https://${req.headers.host}`);
      origins.add(`http://${req.headers.host}`);
    }
  }

  origins.add(`http://localhost:${config.PORT || 3000}`);
  origins.add(`http://127.0.0.1:${config.PORT || 3000}`);
  return Array.from(origins);
}

const PENDING_ENROLLMENT_FILE = path.join(config.DATA_DIR, 'pending-enrollment.json');

function savePendingEnrollmentFile(data) {
  try {
    if (!fs.existsSync(config.DATA_DIR)) {
      fs.mkdirSync(config.DATA_DIR, { recursive: true });
    }
    const tmp = `${PENDING_ENROLLMENT_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, PENDING_ENROLLMENT_FILE);
  } catch (err) {
    console.error('[auth-gateway] Error saving pending-enrollment.json:', err.message);
  }
}

function loadPendingEnrollmentFile() {
  try {
    if (fs.existsSync(PENDING_ENROLLMENT_FILE)) {
      const raw = fs.readFileSync(PENDING_ENROLLMENT_FILE, 'utf8');
      return JSON.parse(raw);
    }
  } catch (_) {}
  return null;
}

function cleanPendingEnrollmentFile() {
  try {
    if (fs.existsSync(PENDING_ENROLLMENT_FILE)) {
      fs.unlinkSync(PENDING_ENROLLMENT_FILE);
    }
  } catch (_) {}
}

function createEnrollmentToken(ttlMs = 5 * 60 * 1000) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + ttlMs;
  const record = {
    token,
    createdAt: Date.now(),
    expiresAt,
    completed: false,
    challenge: null,
  };
  pendingEnrollmentTokens.set(token, record);
  savePendingEnrollmentFile(record);
  const enrollUrl = `${config.server.baseUrl}/auth/enroll-fido?token=${encodeURIComponent(token)}`;
  return { token, enrollUrl, expiresAt };
}

function getEnrollmentToken(token) {
  if (!token || typeof token !== 'string') return null;
  let item = pendingEnrollmentTokens.get(token);
  if (!item) {
    const fileData = loadPendingEnrollmentFile();
    if (fileData && fileData.token === token) {
      item = fileData;
      pendingEnrollmentTokens.set(token, item);
    }
  }
  if (!item) return null;
  if (Date.now() > item.expiresAt || item.completed) {
    pendingEnrollmentTokens.delete(token);
    cleanPendingEnrollmentFile();
    return null;
  }
  return item;
}

async function generateRegistrationOptionsForToken(token, req) {
  const item = getEnrollmentToken(token);
  if (!item) {
    throw new Error('Enrollment token is invalid or has expired.');
  }

  const rpID = getRPID(req);
  const rpName = config.app.name || 'Auth Gateway';

  const excludeCredentials = inMemoryCredentials.map(c => ({
    id: c.id,
    transports: c.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: 'approver',
    userID: new Uint8Array(Buffer.from('approver-master-identity')),
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  item.challenge = options.challenge;
  savePendingEnrollmentFile(item);
  return options;
}

async function verifyRegistrationForToken(token, response, keyName, req) {
  const item = getEnrollmentToken(token);
  if (!item || !item.challenge) {
    throw new Error('Enrollment session has expired or was not initialized.');
  }

  const rpID = getRPID(req);
  const expectedOrigins = getExpectedOrigins(req);

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: item.challenge,
    expectedOrigin: expectedOrigins,
    expectedRPID: rpID,
    requireUserVerification: false,
  });

  if (!verification || !verification.verified || !verification.registrationInfo) {
    throw new Error('FIDO registration verification failed.');
  }

  const { credential } = verification.registrationInfo;
  const credentialId = credential.id;
  const publicKeyBase64 = Buffer.from(credential.publicKey).toString('base64url');

  const existingIdx = inMemoryCredentials.findIndex(c => c.id === credentialId);
  const credRecord = {
    id: credentialId,
    publicKey: publicKeyBase64,
    counter: credential.counter || 0,
    transports: credential.transports || response.response?.transports || [],
    name: (typeof keyName === 'string' && keyName.trim()) ? keyName.trim() : `FIDO Key ${inMemoryCredentials.length + 1}`,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };

  if (existingIdx !== -1) {
    inMemoryCredentials[existingIdx] = credRecord;
  } else {
    inMemoryCredentials.push(credRecord);
  }

  saveCredentials();

  // Mark token completed and activate FIDO mode
  item.completed = true;
  item.credential = { id: credRecord.id, name: credRecord.name };
  savePendingEnrollmentFile(item);
  pendingEnrollmentTokens.delete(token);

  setActiveAuthMethod('fido');
  auditLog('FIDO_KEY_ENROLLED', {
    id: credRecord.id,
    name: credRecord.name,
    ip: req ? (req.ip || req.headers['x-forwarded-for']) : 'terminal',
  });

  enrollmentEvents.emit(`enrolled:${token}`, credRecord);
  return credRecord;
}

async function generateLoginOptions(req) {
  loadCredentials();
  if (inMemoryCredentials.length === 0) {
    throw new Error('No FIDO security keys have been enrolled.');
  }

  const rpID = getRPID(req);
  const allowCredentials = inMemoryCredentials.map(c => ({
    id: c.id,
    transports: c.transports,
  }));

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
  });

  const challengeId = crypto.randomBytes(24).toString('base64url');
  activeAuthChallenges.set(challengeId, {
    challenge: options.challenge,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * 1000, // 60s
  });

  return { challengeId, options };
}

async function verifyLoginResponse(challengeId, response, req) {
  const challengeItem = activeAuthChallenges.get(challengeId);
  activeAuthChallenges.delete(challengeId);

  if (!challengeItem || Date.now() > challengeItem.expiresAt) {
    throw new Error('Authentication challenge expired. Please retry.');
  }

  loadCredentials();
  const credentialId = response.id;
  const storedCred = inMemoryCredentials.find(c => c.id === credentialId);
  if (!storedCred) {
    throw new Error('Security key not recognized or not enrolled.');
  }

  const rpID = getRPID(req);
  const expectedOrigins = getExpectedOrigins(req);

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challengeItem.challenge,
    expectedOrigin: expectedOrigins,
    expectedRPID: rpID,
    credential: {
      id: storedCred.id,
      publicKey: Buffer.from(storedCred.publicKey, 'base64url'),
      counter: storedCred.counter || 0,
      transports: storedCred.transports,
    },
    requireUserVerification: false,
  });

  if (!verification || !verification.verified) {
    throw new Error('WebAuthn signature verification failed.');
  }

  storedCred.counter = verification.authenticationInfo.newCounter;
  storedCred.lastUsedAt = new Date().toISOString();
  saveCredentials();

  return storedCred;
}

// Cleanup expired tokens and challenges every 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [t, item] of pendingEnrollmentTokens.entries()) {
    if (now > item.expiresAt || item.completed) {
      pendingEnrollmentTokens.delete(t);
    }
  }
  for (const [cid, item] of activeAuthChallenges.entries()) {
    if (now > item.expiresAt) {
      activeAuthChallenges.delete(cid);
    }
  }
}, 60 * 1000).unref();

module.exports = {
  loadCredentials,
  saveCredentials,
  inMemoryCredentials,
  getEnrolledCredentials: () => {
    loadCredentials();
    return inMemoryCredentials;
  },
  getActiveAuthMethod,
  setActiveAuthMethod,
  hasEnrolledKeys: () => {
    loadCredentials();
    return inMemoryCredentials.length > 0;
  },
  createEnrollmentToken,
  getEnrollmentToken,
  loadPendingEnrollmentFile,
  cleanPendingEnrollmentFile,
  generateRegistrationOptionsForToken,
  verifyRegistrationForToken,
  generateLoginOptions,
  verifyLoginResponse,
  enrollmentEvents,
};
