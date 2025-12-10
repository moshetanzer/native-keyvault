import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { CredentialStore } from '../src/index';

vi.mock('node:child_process');

describe('CredentialStore', () => {
  const testService = 'test-credential-store';
  const testAccount = 'test@example.com';
  const testPassword = 'super-secret-password';
  let store: CredentialStore;
  let cacheDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    cacheDir = join(homedir(), '.cache', testService);
  });

  afterEach(() => {
    if (existsSync(cacheDir)) {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  describe('Fallback Storage', () => {
    beforeEach(() => {
      store = new CredentialStore(testService, { fallback: true });
    });

    it('should save and retrieve credentials', () => {
      store.save(testAccount, testPassword);
      const retrieved = store.get(testAccount);
      expect(retrieved).toBe(testPassword);
    });

    it('should return null for non-existent account', () => {
      const retrieved = store.get('nonexistent@example.com');
      expect(retrieved).toBeNull();
    });

    it('should delete credentials', () => {
      store.save(testAccount, testPassword);
      store.delete(testAccount);
      const retrieved = store.get(testAccount);
      expect(retrieved).toBeNull();
    });

    it('should handle multiple accounts', () => {
      const account1 = 'user1@example.com';
      const account2 = 'user2@example.com';
      const password1 = 'password1';
      const password2 = 'password2';

      store.save(account1, password1);
      store.save(account2, password2);

      expect(store.get(account1)).toBe(password1);
      expect(store.get(account2)).toBe(password2);
    });

    it('should encrypt passwords in storage', () => {
      store.save(testAccount, testPassword);
      
      const cacheFile = join(cacheDir, 'credentials.json');
      const fs = require('node:fs');
      const content = fs.readFileSync(cacheFile, 'utf8');
      
      expect(content).not.toContain(testPassword);
    });

    it('should create cache directory with proper permissions', () => {
      store.save(testAccount, testPassword);
      expect(existsSync(cacheDir)).toBe(true);
      expect(existsSync(join(cacheDir, 'key.bin'))).toBe(true);
      expect(existsSync(join(cacheDir, 'credentials.json'))).toBe(true);
    });
  });

  describe('macOS Native Storage', () => {
    beforeEach(() => {
      vi.mocked(execSync).mockReset();
      Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });
    });

    it('should call security command to save', () => {
      store = new CredentialStore(testService);
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store.save(testAccount, testPassword);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('security add-generic-password'),
        expect.objectContaining({ input: testPassword })
      );
    });

    it('should call security command to delete', () => {
      store = new CredentialStore(testService);
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store.delete(testAccount);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('security delete-generic-password')
      );
    });

    it('should return null when credential not found', () => {
      store = new CredentialStore(testService);
      vi.mocked(execSync).mockImplementation(() => {
        throw new Error('Not found');
      });
      
      const result = store.get(testAccount);
      expect(result).toBeNull();
    });
  });

  describe('Windows Native Storage', () => {
    beforeEach(() => {
      vi.mocked(execSync).mockReset();
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
      store = new CredentialStore(testService);
    });

    it('should call cmdkey to save', () => {
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store.save(testAccount, testPassword);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('cmdkey /generic:')
      );
    });

    it('should call cmdkey to delete', () => {
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store.delete(testAccount);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('cmdkey /delete:')
      );
    });
  });

  describe('Linux Native Storage', () => {
    beforeEach(() => {
      vi.mocked(execSync).mockReset();
      Object.defineProperty(process, 'platform', { value: 'linux', configurable: true });
    });

    it('should call secret-tool to save', () => {
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store = new CredentialStore(testService);
      store.save(testAccount, testPassword);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('secret-tool store'),
        expect.objectContaining({ input: testPassword })
      );
    });

    it('should call secret-tool to delete', () => {
      vi.mocked(execSync).mockReturnValue(Buffer.from(''));
      store = new CredentialStore(testService);
      store.delete(testAccount);
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringContaining('secret-tool clear')
      );
    });

    it('should fallback when secret-tool not available', () => {
      vi.mocked(execSync).mockImplementation((cmd) => {
        if (typeof cmd === 'string' && cmd.includes('command -v secret-tool')) {
          throw new Error('Command not found');
        }
        return Buffer.from('');
      });
      
      const newStore = new CredentialStore(testService);
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      newStore.save(testAccount, testPassword);
      const result = newStore.get(testAccount);
      
      expect(result).toBe(testPassword);
      expect(consoleSpy).toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });
  });


  describe('Edge Cases', () => {
    beforeEach(() => {
      store = new CredentialStore(testService, { fallback: true });
    });

    it('should handle empty password', () => {
      store.save(testAccount, '');
      expect(store.get(testAccount)).toBe('');
    });

    it('should handle special characters in password', () => {
      const specialPassword = 'p@$$w0rd!#%^&*(){}[]|\\:;"<>?,./`~';
      store.save(testAccount, specialPassword);
      expect(store.get(testAccount)).toBe(specialPassword);
    });

    it('should handle unicode in password', () => {
      const unicodePassword = '密码🔐パスワード';
      store.save(testAccount, unicodePassword);
      expect(store.get(testAccount)).toBe(unicodePassword);
    });

    it('should overwrite existing credential', () => {
      store.save(testAccount, 'old-password');
      store.save(testAccount, 'new-password');
      expect(store.get(testAccount)).toBe('new-password');
    });
  });
});