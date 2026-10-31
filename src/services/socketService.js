const { Server } = require('socket.io');
const { isAllowedOrigin } = require('../utils/originHelper');

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
