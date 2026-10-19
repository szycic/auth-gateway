#!/usr/bin/env node
/**
 * CLI utility to set or change the Approver Password for Auth Gateway.
 * Computes a secure salted scrypt hash and stores it in the persistent data directory.
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

const argPassword = process.argv[2];

if (argPassword) {
  savePassword(argPassword);
} else {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.question('Enter new approver password: ', (enteredPassword) => {
    rl.close();
    savePassword(enteredPassword);
  });
}
