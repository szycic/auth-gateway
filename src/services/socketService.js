const { Server } = require('socket.io');
const cookie = require('cookie');
const config = require('../config');
const { isAllowedOrigin } = require('../utils/originHelper');
const sessionService = require('./sessionService');

let ioInstance = null;

function initSocketIO(server) {
  const io = new Server(server, {
    cors: {
      origin: (origin, callback) => {
        if (isAllowedOrigin(origin)) {
          return callback(null, true);
        }
        return callback(new Error('CORS origin not allowed: ' + origin));
      },
      methods: ['GET', 'POST'],
      credentials: true,
    },
  });

  io.on('connection', (socket) => {
    // Authenticate client directly from HttpOnly cookies during handshake
    try {
      const rawCookies = (socket.request && socket.request.headers && socket.request.headers.cookie) || '';
      const parsed = cookie.parse(rawCookies);
      const authToken = parsed[config.AUTH_COOKIE_NAME] || parsed['share_auth_token'];
      const approverToken = parsed[config.APPROVER_COOKIE_NAME];

      if (authToken && sessionService.activeSessions.has(authToken)) {
        const s = sessionService.activeSessions.get(authToken);
        if (s && s.id) {
          socket.join('session:' + s.id);
          socket.join('active-desktops');
        }
      }

      if (approverToken && sessionService.approverSessions.has(approverToken)) {
        socket.join('approver:' + approverToken);
        socket.join('active-approvers');
      }
    } catch (_) {}

    socket.on('join-session', (loginSessionId) => {
      if (typeof loginSessionId === 'string' && loginSessionId.trim().length > 0) {
        socket.join(loginSessionId.trim());
      }
    });

    socket.on('register-desktop', (sessionId) => {
      if (typeof sessionId === 'string' && sessionId.trim().length > 0) {
        socket.join('session:' + sessionId.trim());
      }
      socket.join('active-desktops');
    });

    socket.on('register-approver', (approverToken) => {
      if (typeof approverToken === 'string' && approverToken.trim().length > 0) {
        socket.join('approver:' + approverToken.trim());
      }
      socket.join('active-approvers');
    });
  });

  ioInstance = io;
  return io;
}

function getIO() {
  return ioInstance;
}

function notifySessionApproved(loginSessionId, payload) {
  if (ioInstance) {
    ioInstance.to(loginSessionId).emit('approved', payload);
  }
}

function notifySessionRejected(loginSessionId, payload) {
  if (ioInstance) {
    ioInstance.to(loginSessionId).emit('rejected', payload);
  }
}

function notifySessionRevoked(sessionId, token, approverToken) {
  if (ioInstance) {
    const payload = { sessionId };
    if (sessionId) {
      ioInstance.to('session:' + sessionId).emit('session-revoked', payload);
    }
    if (approverToken) {
      ioInstance.to('approver:' + approverToken).emit('session-revoked', payload);
    }
    ioInstance.emit('session-revoked', payload);
  }
}

function notifyAllSessionsRevoked() {
  if (ioInstance) {
    ioInstance.emit('session-revoked', { all: true });
  }
}

function notifySessionPermissionsUpdated(sessionId, allowedServices) {
  if (ioInstance && sessionId) {
    ioInstance.to('session:' + sessionId).emit('session-permissions-updated', { sessionId, allowedServices });
  }
}

function closeSocketIO() {
  if (ioInstance) {
    try {
      ioInstance.close();
    } catch (e) {}
    ioInstance = null;
  }
}

module.exports = {
  initSocketIO,
  getIO,
  closeSocketIO,
  notifySessionApproved,
  notifySessionRejected,
  notifySessionRevoked,
  notifyAllSessionsRevoked,
  notifySessionPermissionsUpdated,
};
