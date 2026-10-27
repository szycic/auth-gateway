#!/usr/bin/env node
/**
 * CLI utility to configure the Approver Login Method:
 * Either Password (scrypt) OR FIDO2 Security Key (YubiKey/Passkey).
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

async function enrollFidoKey() {
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
      return true;
    }

    if (process.stdout.isTTY) {
      process.stdout.write(`\r⏳ Waiting for security key touch... (Press Ctrl+C to cancel) ${spinner[spinIdx]}`);
      spinIdx = (spinIdx + 1) % spinner.length;
    }

    await wait(600);
  }

  cleanup();
  console.log('\n\n❌ Error: Enrollment session timed out (5 minutes).\n');
  return false;
}

async function main() {
  const currentMethod = webauthnService.getActiveAuthMethod();
  const enrolledKeys = webauthnService.getEnrolledCredentials();

  console.log('\n======================================================');
  console.log('       Auth Gateway — Approver Login Method');
  console.log('======================================================');
  console.log(`Current Active Method : ${currentMethod === 'fido' ? 'FIDO2 Security Key' : 'Password (scrypt)'}`);
  console.log(`Registered FIDO Keys  : ${enrolledKeys.length} key(s)`);
  if (enrolledKeys.length > 0) {
    enrolledKeys.forEach((k, i) => {
      console.log(`   ${i + 1}) ${k.name || 'FIDO Key'} (${k.createdAt ? new Date(k.createdAt).toLocaleDateString() : 'N/A'})`);
    });
  }
  console.log('======================================================\n');

  console.log('Select approver login method:');
  console.log('  1) Password (scrypt)');
  console.log('  2) FIDO2 Security Key (YubiKey / Passkey)\n');

  const choice = await askQuestion('Enter choice [1-2]: ');

  if (choice === '1') {
    webauthnService.setActiveAuthMethod('password');
    console.log('\n======================================================');
    console.log('✅ Approver Login Method set to: Password');
    console.log('======================================================');
    console.log('Approvers will now sign in using their master password.');
    console.log('(To change or set your master password, run: npm run set-password)\n');
    process.exit(0);
  }

  if (choice === '2') {
    if (enrolledKeys.length === 0) {
      console.log('\nNo FIDO keys currently registered. Starting enrollment session...');
      const success = await enrollFidoKey();
      process.exit(success ? 0 : 1);
    } else {
      webauthnService.setActiveAuthMethod('fido');
      console.log('\n======================================================');
      console.log('✅ Approver Login Method set to: FIDO2 Security Key');
      console.log('======================================================');
      console.log('Approvers will now sign in using their registered security key.\n');

      const addMore = await askQuestion('Would you like to register an additional FIDO key now? [y/N]: ');
      if (['y', 'yes'].includes(addMore.toLowerCase())) {
        const success = await enrollFidoKey();
        process.exit(success ? 0 : 1);
      }
      process.exit(0);
    }
  }

  console.error('\n❌ Invalid choice. Exiting without changes.\n');
  process.exit(1);
}

main().catch(err => {
  console.error('\n❌ Unexpected error:', err.message);
  process.exit(1);
});
