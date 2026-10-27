#!/usr/bin/env node
/**
 * CLI utility to set or change the Approver Password for Auth Gateway.
 * Prompts for password securely (masked input with confirmation) and stores salted scrypt hash.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PASSWORD_FILE = path.join(DATA_DIR, 'password.json');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt}$${key.toString('hex')}`;
}

function getSessionStats() {
  const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
  let userSessions = 0;
  let approverSessions = 0;

  if (fs.existsSync(SESSIONS_FILE)) {
    try {
      const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
      const data = JSON.parse(raw);
      if (Array.isArray(data.activeSessions)) {
        userSessions = data.activeSessions.length;
      }
      if (Array.isArray(data.approverSessions)) {
        approverSessions = data.approverSessions.length;
      }
    } catch (_) {}
  }

  return { userSessions, approverSessions, total: userSessions + approverSessions };
}

function savePassword(password, shouldLogout = false) {
  const trimmed = password.trim();
  if (trimmed.length < 10) {
    console.error('\n❌ Error: Password must be at least 10 characters long.\n');
    process.exit(1);
  }

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const hash = hashPassword(trimmed);
  const payload = {
    approverPasswordHash: hash,
    updatedAt: new Date().toISOString(),
  };

  fs.writeFileSync(PASSWORD_FILE, JSON.stringify(payload, null, 2), 'utf8');

  // Ensure active login method is set to password
  try {
    const authMethodFile = path.join(DATA_DIR, 'auth-method.json');
    const methodPayload = {
      method: 'password',
      updatedAt: new Date().toISOString(),
    };
    const tmpMethod = `${authMethodFile}.tmp`;
    fs.writeFileSync(tmpMethod, JSON.stringify(methodPayload, null, 2), 'utf8');
    fs.renameSync(tmpMethod, authMethodFile);
  } catch (_) {}

  let invalidatedUserCount = 0;
  let invalidatedApproverCount = 0;

  if (shouldLogout) {
    const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
    if (fs.existsSync(SESSIONS_FILE)) {
      try {
        const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
        const data = JSON.parse(raw);
        if (Array.isArray(data.activeSessions)) {
          invalidatedUserCount = data.activeSessions.length;
          data.activeSessions = [];
        }
        if (Array.isArray(data.approverSessions)) {
          invalidatedApproverCount = data.approverSessions.length;
          data.approverSessions = [];
        }
        data.lastSaved = new Date().toISOString();
        const tmp = `${SESSIONS_FILE}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
        fs.renameSync(tmp, SESSIONS_FILE);
      } catch (err) {
        console.warn('⚠️  Could not clear sessions.json:', err.message);
      }
    }
  }

  console.log('\n======================================================');
  console.log('✅ Approver Password Successfully Configured!');
  console.log('======================================================');
  console.log(`Saved salted scrypt hash to: ${PASSWORD_FILE}`);
  if (shouldLogout) {
    console.log(`Invalidated every session (${invalidatedUserCount} user session(s), ${invalidatedApproverCount} approver session(s)).`);
  } else {
    console.log('Existing sessions were preserved (no sessions logged out).');
  }
  console.log('The new password takes effect immediately (no restart needed).\n');
}

let nonTtyLines = null;
let nonTtyIndex = 0;

function getNonTtyLine() {
  if (!nonTtyLines) {
    try {
      const raw = fs.readFileSync(0, 'utf8');
      nonTtyLines = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    } catch (e) {
      nonTtyLines = [];
    }
  }
  return nonTtyLines[nonTtyIndex++] || '';
}

/**
 * Prompts for input securely without printing plaintext to the terminal.
 * Masks typed characters with asterisks (*).
 */
function readSecret(promptText) {
  // If input is non-interactive (e.g. piped or redirected stdin)
  if (!process.stdin.isTTY) {
    return Promise.resolve(getNonTtyLine());
  }

  return new Promise((resolve) => {
    process.stdout.write(promptText);

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    let input = '';

    const onData = (chunk) => {
      for (let i = 0; i < chunk.length; i++) {
        const char = chunk[i];
        if (char === '\n' || char === '\r' || char === '\u0004') {
          // Enter or EOF
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(input);
          return;
        } else if (char === '\u0003') {
          // Ctrl+C
          process.stdout.write('\n');
          process.exit(130);
        } else if (char === '\u0008' || char === '\x7f') {
          // Backspace
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          input += char;
          process.stdout.write('*');
        }
      }
    };

    process.stdin.on('data', onData);
  });
}

/**
 * Prompts for plain text input.
 */
function askQuestion(promptText) {
  if (!process.stdin.isTTY) {
    return Promise.resolve(getNonTtyLine());
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(promptText, (ans) => {
      rl.close();
      resolve(ans.trim());
    });
  });
}

async function main() {
  const args = process.argv.slice(2);
  let shouldLogout = null;

  if (args.includes('--logout-all') || args.includes('--logout-sessions') || args.includes('-y')) {
    shouldLogout = true;
  } else if (args.includes('--no-logout') || args.includes('--keep-sessions') || args.includes('-n')) {
    shouldLogout = false;
  }

  const hasPositionalArg = args.find(a => !a.startsWith('-'));
  if (hasPositionalArg) {
    console.warn('\n⚠️  Security Notice: Passing passwords as command-line arguments is insecure');
    console.warn('   because it exposes them in process listings (ps) and shell history (.bash_history).\n');
    console.warn('   Please enter your password securely at the prompt below.\n');
  }

  console.log('\n=== Configure Approver Password ===');
  console.log('Password must be at least 10 characters long.\n');

  const password = await readSecret('Enter new approver password: ');

  if (!password || password.trim().length < 10) {
    console.error('\n❌ Error: Password must be at least 10 characters long.\n');
    process.exit(1);
  }

  const confirm = await readSecret('Confirm new approver password: ');

  if (password !== confirm) {
    console.error('\n❌ Error: Passwords do not match. Please try again.\n');
    process.exit(1);
  }

  if (shouldLogout === null) {
    const stats = getSessionStats();
    if (stats.total > 0) {
      console.log(`\nActive sessions detected: ${stats.userSessions} user session(s), ${stats.approverSessions} approver session(s).`);
    }
    const answer = await askQuestion('\nDo you want to log out every session? [y/N]: ');
    shouldLogout = ['y', 'yes'].includes(answer.toLowerCase());
  }

  savePassword(password, shouldLogout);
}

main().catch((err) => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
