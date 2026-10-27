#!/usr/bin/env node
/**
 * CLI utility to register a FIDO Security Key and set active login method to FIDO.
 * Generates a single-use 5-minute direct link and waits for physical touch in the browser.
 */
const webauthnService = require('./src/services/webauthnService');

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log('\n======================================================');
  console.log('       Auth Gateway — FIDO Security Key Setup');
  console.log('======================================================\n');

  const existingKeys = webauthnService.getEnrolledCredentials();
  if (existingKeys.length > 0) {
    console.log(`Currently registered FIDO key(s) (${existingKeys.length}):`);
    existingKeys.forEach((k, idx) => {
      const created = k.createdAt ? new Date(k.createdAt).toLocaleDateString() : 'N/A';
      console.log(`  ${idx + 1}. ${k.name || 'Unnamed Key'} (Added: ${created})`);
    });
    console.log('');
  }

  const { token, enrollUrl, expiresAt } = webauthnService.createEnrollmentToken();

  const cleanup = () => {
    webauthnService.cleanPendingEnrollmentFile();
  };

  process.on('SIGINT', () => {
    cleanup();
    console.log('\n\nRegistration cancelled.\n');
    process.exit(130);
  });

  process.on('SIGTERM', () => {
    cleanup();
    process.exit(143);
  });

  console.log('Open this link in your browser to register your FIDO key:\n');
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
      process.exit(0);
    }

    if (process.stdout.isTTY) {
      process.stdout.write(`\r⏳ Waiting for security key touch... (Press Ctrl+C to cancel) ${spinner[spinIdx]}`);
      spinIdx = (spinIdx + 1) % spinner.length;
    }

    await wait(600);
  }

  cleanup();
  console.log('\n\n❌ Error: Enrollment session timed out (5 minutes). Please run the command again.\n');
  process.exit(1);
}

main().catch(err => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
