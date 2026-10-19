#!/usr/bin/env node
/**
 * Utility script to generate a secure salted scrypt hash for APPROVER_PASSWORD_HASH
 */
const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const key = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt}$${key.toString('hex')}`;
}

const password = process.argv[2];

if (!password) {
  console.error('Usage: node hash.js <password>');
  console.error('Example: node hash.js "MySecurePass123"');
  process.exit(1);
}

const hash = hashPassword(password);
console.log('\n======================================================');
console.log('Generated Salted Password Hash (scrypt):');
console.log('======================================================');
console.log(`APPROVER_PASSWORD_HASH=${hash}`);
console.log('======================================================');
console.log('Add the line above to your .env or docker-compose.yml.\n');
