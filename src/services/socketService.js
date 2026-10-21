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

function notifySessionRevoked(sessionId, token) {
  if (ioInstance) {
    ioInstance.to('session:' + sessionId).emit('session-revoked', { sessionId, token });
    ioInstance.emit('session-revoked', { sessionId, token });
  }
}

function notifyAllSessionsRevoked() {
  if (ioInstance) {
    ioInstance.emit('session-revoked', { all: true });
  }
}

module.exports = {
  initSocketIO,
  getIO,
  notifySessionApproved,
  notifySessionRejected,
  notifySessionRevoked,
  notifyAllSessionsRevoked,
};
