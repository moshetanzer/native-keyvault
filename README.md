# Native Keyvault

A cross-platform Node.js credential storage library that securely stores passwords using native OS credential managers with an encrypted fallback option.

## Features

- **Cross-platform support**: macOS (Keychain), Windows (Credential Manager), Linux (libsecret)
- **Automatic fallback**: Falls back to encrypted file storage if native storage fails
- **Secure encryption**: AES-256-GCM encryption for fallback storage
- **Simple API**: Just three methods: `save()`, `get()`, and `delete()`

## Installation

```bash
pnpm add native-keyvault
```

### Platform Requirements

**Linux only**: Requires `libsecret-tools` for native credential storage:

```bash
sudo apt-get install libsecret-tools
```

macOS and Windows have native support built into the OS.

## Usage

```typescript
import { CredentialStore } from 'native-keyvault'

const store = new CredentialStore('my-app')

store.save('user@example.com', 'my-secure-password')

const password = store.get('user@example.com')
console.log(password)

store.delete('user@example.com')
```

### Force Fallback Mode

If you want to always use encrypted file storage instead of the native credential manager:

```typescript
const store = new CredentialStore('my-app', { fallback: true })
```

## API

### `new CredentialStore(service, options?)`

Creates a new credential store instance.

- `service` (string): Identifier for your application
- `options.fallback` (boolean): Force fallback storage instead of native. Default: `false`

### `save(account, password)`

Saves a credential.

- `account` (string): Account identifier (e.g., email, username)
- `password` (string): Password to store

### `get(account): string | null`

Retrieves a credential.

- `account` (string): Account identifier
- Returns: Password string or `null` if not found

### `delete(account)`

Deletes a credential.

- `account` (string): Account identifier to delete

## How It Works

1. **Native Storage** (default): Uses OS-specific credential managers
   - macOS: Keychain via `security` command
   - Windows: Credential Manager via `cmdkey`
   - Linux: libsecret via `secret-tool`

2. **Fallback Storage**: If native storage fails or is unavailable
   - Stores encrypted credentials in `~/.cache/{service}/credentials.json`
   - Uses AES-256-GCM encryption with a randomly generated key
   - Key stored in `~/.cache/{service}/key.bin` with restricted permissions (600)

## Security Considerations

- Passwords are passed to native tools via stdin to avoid process list exposure
- Fallback encryption uses industry-standard AES-256-GCM
- Fallback storage files are created with restricted permissions (owner read/write only)
- Native credential managers provide OS-level security features

## License

MIT
