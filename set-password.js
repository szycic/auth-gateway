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

function savePassword(password) {
  const trimmed = password.trim();
  if (trimmed.length < 6) {
    console.error('\n❌ Error: Password must be at least 6 characters long.\n');
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

  console.log('\n======================================================');
  console.log('✅ Approver Password Successfully Configured!');
  console.log('======================================================');
  console.log(`Saved salted scrypt hash to: ${PASSWORD_FILE}`);
  console.log('The new password takes effect immediately (no restart needed).\n');
}

/**
 * Prompts for input securely without printing plaintext to the terminal.
 * Masks typed characters with asterisks (*).
 */
function readSecret(promptText) {
  return new Promise((resolve) => {
    // If input is non-interactive (e.g. piped or redirected stdin)
    if (!process.stdin.isTTY) {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question(promptText, (ans) => {
        rl.close();
        resolve(ans ? ans.trim() : '');
      });
      return;
    }

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

async function main() {
  if (process.argv[2]) {
    console.warn('\n⚠️  Security Notice: Passing passwords as command-line arguments is insecure');
    console.warn('   because it exposes them in process listings (ps) and shell history (.bash_history).\n');
    console.warn('   Please enter your password securely at the prompt below.\n');
  }

  console.log('\n=== Configure Approver Password ===');
  console.log('Password must be at least 6 characters long.\n');

  const password = await readSecret('Enter new approver password: ');

  if (!password || password.trim().length < 6) {
    console.error('\n❌ Error: Password must be at least 6 characters long.\n');
    process.exit(1);
  }

  const confirm = await readSecret('Confirm new approver password: ');

  if (password !== confirm) {
    console.error('\n❌ Error: Passwords do not match. Please try again.\n');
    process.exit(1);
  }

  savePassword(password);
}

main().catch((err) => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
