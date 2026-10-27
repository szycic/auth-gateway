#!/usr/bin/env node
/**
 * CLI utility to manage FIDO Security Keys (enroll, list, and revoke keys).
 * Automatically switches active login method to FIDO when a key is registered.
 */
const readline = require('readline');
const webauthnService = require('./src/services/webauthnService');

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function askQuestion(promptText) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise(resolve => {
    rl.question(promptText, ans => {
      rl.close();
      resolve(ans.trim());
    });
  });
}

function printHeader() {
  console.log('\n======================================================');
  console.log('       Auth Gateway — FIDO Security Key Manager');
  console.log('======================================================');
}

function listKeys() {
  const keys = webauthnService.getEnrolledCredentials();
  if (keys.length === 0) {
    console.log('No FIDO keys currently registered.\n');
    return keys;
  }

  console.log(`Currently registered FIDO key(s) (${keys.length}):`);
  keys.forEach((k, idx) => {
    const created = k.createdAt ? new Date(k.createdAt).toLocaleDateString() : 'N/A';
    const lastUsed = k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'Never';
    console.log(`  ${idx + 1}. \x1b[1m${k.name || 'FIDO Key'}\x1b[0m (Added: ${created}, Last used: ${lastUsed})`);
    console.log(`     ID: ${k.id.slice(0, 24)}...`);
  });
  console.log('');
  return keys;
}

async function startEnrollmentLoop() {
  const { token, enrollUrl, expiresAt } = webauthnService.createEnrollmentToken();

  const cleanup = () => {
    webauthnService.cleanPendingEnrollmentFile();
  };

  process.on('SIGINT', () => {
    cleanup();
    console.log('\n\nRegistration cancelled.\n');
    process.exit(130);
  });

  console.log('\nOpen this link in your browser to register your FIDO key:\n');
  console.log(`🔗 \x1b[1m\x1b[36m${enrollUrl}\x1b[0m\n`);
  process.stdout.write('⏳ Waiting for security key touch... (Press Ctrl+C to cancel) ');

  const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let spinIdx = 0;

  while (Date.now() < expiresAt) {
    const pending = webauthnService.loadPendingEnrollmentFile();
    if (pending && pending.token === token && pending.completed) {
      cleanup();
      const cred = pending.credential || {};
      process.stdout.write('\r\x1b[K');
      console.log('\n======================================================');
      console.log('✅ FIDO Security Key Successfully Registered!');
      console.log('======================================================');
      console.log(`   Label: ${cred.name || 'FIDO Key'}`);
      if (cred.id) console.log(`   Credential ID: ${cred.id}`);
      console.log('   Active Approver Login Method is now: FIDO Security Key');
      console.log('The new method takes effect immediately (no restart needed).\n');

      // Prompt to add a backup key if this was their only key
      const currentKeys = webauthnService.getEnrolledCredentials();
      if (currentKeys.length === 1) {
        console.log('💡 Tip: Having a secondary backup key ensures you are never');
        console.log('   locked out of your homelab if your primary key is lost.\n');
        const addBackup = await askQuestion('Would you like to register a backup key now? [y/N]: ');
        if (['y', 'yes'].includes(addBackup.toLowerCase())) {
          return startEnrollmentLoop();
        }
      }
      return true;
    }

    if (process.stdout.isTTY) {
      process.stdout.write(`\r⏳ Waiting for security key touch... (Press Ctrl+C to cancel) ${spinner[spinIdx]}`);
      spinIdx = (spinIdx + 1) % spinner.length;
    }

    await wait(600);
  }

  cleanup();
  console.log('\n\n❌ Error: Enrollment session timed out (5 minutes). Please run the command again.\n');
  return false;
}

async function revokeKey(targetArg) {
  const keys = webauthnService.getEnrolledCredentials();
  if (keys.length === 0) {
    console.log('\nNo FIDO keys to revoke.\n');
    return false;
  }

  let selectedKey = null;

  if (targetArg) {
    const num = parseInt(targetArg, 10);
    if (!isNaN(num) && num >= 1 && num <= keys.length) {
      selectedKey = keys[num - 1];
    } else {
      selectedKey = keys.find(k => k.id === targetArg || k.name.toLowerCase() === targetArg.toLowerCase());
    }
  }

  if (!selectedKey) {
    listKeys();
    const ans = await askQuestion(`Enter key number to delete [1-${keys.length}]: `);
    const num = parseInt(ans, 10);
    if (isNaN(num) || num < 1 || num > keys.length) {
      console.error('\n❌ Invalid selection. Operation aborted.\n');
      return false;
    }
    selectedKey = keys[num - 1];
  }

  const confirm = await askQuestion(`Are you sure you want to permanently revoke "${selectedKey.name}"? [y/N]: `);
  if (!['y', 'yes'].includes(confirm.toLowerCase())) {
    console.log('\nRevocation cancelled.\n');
    return false;
  }

  const removed = webauthnService.deleteCredential(selectedKey.id);
  if (removed) {
    console.log('\n======================================================');
    console.log(`✅ Revoked FIDO Key: "${removed.name}"`);
    console.log('======================================================');
    const remaining = webauthnService.getEnrolledCredentials();
    if (remaining.length === 0) {
      console.log('⚠️  All FIDO keys have been removed.');
      console.log('   Active approver login method automatically switched to: Password\n');
    } else {
      console.log(`Remaining registered FIDO keys: ${remaining.length}\n`);
    }
    return true;
  } else {
    console.error('\n❌ Failed to revoke key.\n');
    return false;
  }
}

async function main() {
  const args = process.argv.slice(2);

  printHeader();

  if (args.includes('--list') || args.includes('-l')) {
    listKeys();
    process.exit(0);
  }

  if (args.includes('--add') || args.includes('-a')) {
    const ok = await startEnrollmentLoop();
    process.exit(ok ? 0 : 1);
  }

  const delIdx = args.findIndex(a => a === '--delete' || a === '-d' || a === '--revoke');
  if (delIdx !== -1) {
    const target = args[delIdx + 1];
    const ok = await revokeKey(target);
    process.exit(ok ? 0 : 1);
  }

  const existingKeys = webauthnService.getEnrolledCredentials();

  // If no keys yet, jump straight to enrolling the first key
  if (existingKeys.length === 0) {
    console.log('No FIDO keys currently registered. Starting initial enrollment session...\n');
    const ok = await startEnrollmentLoop();
    process.exit(ok ? 0 : 1);
  }

  // Interactive menu
  listKeys();
  console.log('Select action:');
  console.log('  1) Register an additional FIDO key');
  console.log('  2) Revoke / delete an existing key');
  console.log('  3) Exit\n');

  const choice = await askQuestion('Enter choice [1-3]: ');

  if (choice === '1') {
    const ok = await startEnrollmentLoop();
    process.exit(ok ? 0 : 1);
  } else if (choice === '2') {
    const ok = await revokeKey();
    process.exit(ok ? 0 : 1);
  } else if (choice === '3') {
    console.log('\nExiting.\n');
    process.exit(0);
  } else {
    console.error('\n❌ Invalid choice. Exiting.\n');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
