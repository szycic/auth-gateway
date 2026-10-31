#!/usr/bin/env node
/**
 * Utility script to generate a secure salted scrypt hash for APPROVER_PASSWORD_HASH.
 * Prompts for password securely (masked input) to avoid leaving plaintext passwords
 * in shell history or process tables.
 */
const fs = require('fs');
const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt}$${key.toString('hex')}`;
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

function readSecret(promptText) {
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
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(input);
        } else if (char === '\u0003') {
          // Ctrl+C
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdout.write('\n');
          process.exit(130);
        } else if (char === '\b' || char === '\x7f') {
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
  let password = process.argv[2];

  if (password) {
    console.warn('\n⚠️  Security Notice: Passing passwords as command-line arguments is insecure');
    console.warn('   because it may be visible in process tables and shell history.');
    console.warn('   Please enter your password securely at the prompt below.\n');
  } else {
    console.log('\n=== Generate Salted Password Hash (scrypt) ===');
    console.log('Password must be at least 10 characters long.\n');
    password = await readSecret('Enter password to hash: ');
  }

  const trimmed = (password || '').trim();
  if (trimmed.length < 10) {
    console.error('\n❌ Error: Password must be at least 10 characters long.\n');
    process.exit(1);
  }

  const hash = hashPassword(trimmed);
  console.log('\n======================================================');
  console.log('Generated Salted Password Hash (scrypt):');
  console.log('======================================================');
  console.log(`APPROVER_PASSWORD_HASH=${hash}`);
  console.log('======================================================');
  console.log('Add the line above to your .env or docker-compose.yml.\n');
}

main().catch((err) => {
  console.error('\n❌ Error:', err.message);
  process.exit(1);
});
