#!/usr/bin/env node

import { Command } from 'commander';
import { CredentialStore } from './index';
import * as readline from 'node:readline';
import { stdin as input, stdout as output } from 'node:process';

const program = new Command();

function promptPassword(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input, output });
    
    output.write(prompt);
    input.setRawMode?.(true);
    
    let password = '';
    
    input.on('data', (char) => {
      const byte = char.toString();
      
      if (byte === '\n' || byte === '\r' || byte === '\u0004') {
        input.setRawMode?.(false);
        rl.close();
        output.write('\n');
        resolve(password);
      } else if (byte === '\u0003') {
        process.exit(0);
      } else if (byte === '\u007f' || byte === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          output.write('\b \b');
        }
      } else {
        password += byte;
        output.write('*');
      }
    });
  });
}

program
  .name('keyvault')
  .description('Cross-platform credential storage CLI')
  .version('1.0.0');

program
  .command('save')
  .description('Save a credential')
  .requiredOption('-s, --service <service>', 'Service name')
  .requiredOption('-a, --account <account>', 'Account identifier')
  .option('-p, --password <password>', 'Password (will prompt if not provided)')
  .option('--fallback', 'Force fallback storage')
  .action(async (options) => {
    try {
      const store = new CredentialStore(options.service, { fallback: options.fallback });
      const password = options.password || await promptPassword('Password: ');
      
      store.save(options.account, password);
      console.log(`✓ Credential saved for ${options.account}`);
    } catch (error) {
      console.error(`✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program
  .command('get')
  .description('Retrieve a credential')
  .requiredOption('-s, --service <service>', 'Service name')
  .requiredOption('-a, --account <account>', 'Account identifier')
  .option('--fallback', 'Force fallback storage')
  .option('--show', 'Show password in plain text (default: hidden)')
  .action((options) => {
    try {
      const store = new CredentialStore(options.service, { fallback: options.fallback });
      const password = store.get(options.account);
      
      if (password === null) {
        console.log(`✗ No credential found for ${options.account}`);
        process.exit(1);
      }
      
      if (options.show) {
        console.log(password);
      } else {
        console.log(`✓ Credential found for ${options.account}`);
        console.log('Use --show to display the password');
      }
    } catch (error) {
      console.error(`✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program
  .command('delete')
  .description('Delete a credential')
  .requiredOption('-s, --service <service>', 'Service name')
  .requiredOption('-a, --account <account>', 'Account identifier')
  .option('--fallback', 'Force fallback storage')
  .action((options) => {
    try {
      const store = new CredentialStore(options.service, { fallback: options.fallback });
      store.delete(options.account);
      console.log(`✓ Credential deleted for ${options.account}`);
    } catch (error) {
      console.error(`✗ Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program
  .command('test')
  .description('Test credential storage (save, retrieve, delete)')
  .requiredOption('-s, --service <service>', 'Service name')
  .option('--fallback', 'Force fallback storage')
  .action(async (options) => {
    try {
      const store = new CredentialStore(options.service, { fallback: options.fallback });
      const testAccount = 'test@example.com';
      const testPassword = 'test-password-123';
      
      console.log('Testing credential storage...\n');
      
      console.log('1. Saving credential...');
      store.save(testAccount, testPassword);
      console.log('   ✓ Saved\n');
      
      console.log('2. Retrieving credential...');
      const retrieved = store.get(testAccount);
      console.log(retrieved)
      if (retrieved === testPassword) {
        console.log('   ✓ Retrieved successfully\n');
      } else {
        throw new Error('Retrieved password does not match');
      }
      
      console.log('3. Deleting credential...');
      store.delete(testAccount);
      console.log('   ✓ Deleted\n');
      
      console.log('4. Verifying deletion...');
      const afterDelete = store.get(testAccount);
      if (afterDelete === null) {
        console.log('   ✓ Verified\n');
      } else {
        throw new Error('Credential still exists after deletion');
      }
      
      console.log('✓ All tests passed!');
    } catch (error) {
      console.error(`✗ Test failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program.parse();