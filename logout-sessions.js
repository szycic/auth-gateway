#!/usr/bin/env node
/**
 * CLI utility to log out / invalidate active sessions in Auth Gateway.
 * Prompts whether to log out only user sessions, approver sessions, or both.
 */
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

let nonTtyLines = null;
let nonTtyIndex = 0;

function getNonTtyLine() {
  if (!nonTtyLines) {
    try {
      const raw = fs.readFileSync(0, 'utf8');
      nonTtyLines = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    } catch (_) {
      nonTtyLines = [];
    }
  }
  return nonTtyLines[nonTtyIndex++] || '';
}

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

function printUsage() {
  console.log(`
Usage:
  node logout-sessions.js [options]
  npm run logout-sessions [-- options]

Options:
  -u, --user, --users         Log out only user sessions (desktop/browser access)
  -a, --approver, --approvers Log out only approver sessions (mobile approval devices)
  -b, --both, --all           Log out both user and approver sessions (every session)
  -h, --help                  Show this help screen
`);
}

function readSessionsData() {
  if (!fs.existsSync(SESSIONS_FILE)) {
    return {
      activeSessions: [],
      approverSessions: [],
      exists: false,
    };
  }

  try {
    const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      activeSessions: Array.isArray(data.activeSessions) ? data.activeSessions : [],
      approverSessions: Array.isArray(data.approverSessions) ? data.approverSessions : [],
      raw: data,
      exists: true,
    };
  } catch (err) {
    console.error(`❌ Error reading sessions file at ${SESSIONS_FILE}:`, err.message);
    process.exit(1);
  }
}

function parseTargetChoice(input) {
  const norm = input.trim().toLowerCase();
  if (['1', 'user', 'users', 'u'].includes(norm)) {
    return 'user';
  }
  if (['2', 'approver', 'approvers', 'a', 'app'].includes(norm)) {
    return 'approver';
  }
  if (['3', 'both', 'all', 'b', 'every', 'everything'].includes(norm)) {
    return 'both';
  }
  if (['4', 'cancel', 'c', 'q', 'quit', 'exit', 'n', 'no'].includes(norm)) {
    return 'cancel';
  }
  return null;
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  let target = null;
  if (args.includes('-u') || args.includes('--user') || args.includes('--users')) {
    target = 'user';
  } else if (args.includes('-a') || args.includes('--approver') || args.includes('--approvers')) {
    target = 'approver';
  } else if (args.includes('-b') || args.includes('--both') || args.includes('--all')) {
    target = 'both';
  }

  const sessionInfo = readSessionsData();
  const userCount = sessionInfo.activeSessions.length;
  const approverCount = sessionInfo.approverSessions.length;
  const totalCount = userCount + approverCount;

  console.log('\n======================================================');
  console.log('       Auth Gateway - Session Management');
  console.log('======================================================');
  console.log(`Sessions file: ${SESSIONS_FILE}`);
  console.log('\nCurrent Active Sessions:');
  console.log(`  • User sessions:     ${userCount} active`);
  console.log(`  • Approver sessions: ${approverCount} active`);
  console.log(`  • Total active:      ${totalCount}`);
  console.log('------------------------------------------------------');

  if (totalCount === 0 && !sessionInfo.exists) {
    console.log('ℹ️  No sessions file found on disk. Nothing to log out.\n');
    process.exit(0);
  }

  if (!target) {
    console.log('Which sessions do you want to log out?');
    console.log('  1) Only user sessions');
    console.log('  2) Only approver sessions');
    console.log('  3) Both (user & approver sessions)');
    console.log('  4) Cancel (keep all sessions)\n');

    const ans = await askQuestion('Select an option [1-4, or user/approver/both/cancel, default: 3]: ');
    if (!ans) {
      target = 'both';
    } else {
      target = parseTargetChoice(ans);
    }
  }

  if (target === 'cancel') {
    console.log('\n🚫 Operation cancelled. No sessions were modified.\n');
    process.exit(0);
  }

  if (!target) {
    console.error('\n❌ Invalid option selected. Operation aborted.\n');
    process.exit(1);
  }

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const data = sessionInfo.raw || { activeSessions: [], approverSessions: [] };
  let revokedUserCount = 0;
  let revokedApproverCount = 0;

  if (target === 'user' || target === 'both') {
    revokedUserCount = Array.isArray(data.activeSessions) ? data.activeSessions.length : 0;
    data.activeSessions = [];
  }

  if (target === 'approver' || target === 'both') {
    revokedApproverCount = Array.isArray(data.approverSessions) ? data.approverSessions.length : 0;
    data.approverSessions = [];
  }

  data.lastSaved = new Date().toISOString();

  try {
    const tmp = `${SESSIONS_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, SESSIONS_FILE);
  } catch (err) {
    console.error(`\n❌ Failed to update sessions file:`, err.message);
    process.exit(1);
  }

  const remainingUsers = Array.isArray(data.activeSessions) ? data.activeSessions.length : 0;
  const remainingApprovers = Array.isArray(data.approverSessions) ? data.approverSessions.length : 0;

  console.log('\n======================================================');
  console.log('✅ Sessions Successfully Logged Out!');
  console.log('======================================================');
  if (target === 'user') {
    console.log(`• Logged out: ${revokedUserCount} user session(s)`);
    console.log(`• Preserved:  ${remainingApprovers} approver session(s)`);
  } else if (target === 'approver') {
    console.log(`• Logged out: ${revokedApproverCount} approver session(s)`);
    console.log(`• Preserved:  ${remainingUsers} user session(s)`);
  } else {
    console.log(`• Logged out: ${revokedUserCount} user session(s) and ${revokedApproverCount} approver session(s) (all sessions)`);
  }
  console.log(`\nRemaining active sessions: ${remainingUsers} user, ${remainingApprovers} approver.`);
  console.log('The change takes effect immediately (no restart needed).\n');
}

main().catch((err) => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
