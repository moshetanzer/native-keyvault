import { execSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs, { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path, { join } from 'node:path'

export class CredentialStore {
  private service: string
  private useFallback: boolean

  private cacheDir = ''
  private cacheFile = ''
  private keyFile = ''

  constructor(service: string, options?: { fallback?: boolean }) {
    this.service = service
    this.useFallback = options?.fallback ?? false

    this.cacheDir = join(homedir(), '.cache', this.service)
    this.cacheFile = join(this.cacheDir, 'credentials.json')
    this.keyFile = join(this.cacheDir, 'key.bin')
  }

  save(account: string, password: string) {
    try {
      if (!this.useFallback)
        this._saveNative(account, password)
      else this._saveFallback(account, password)
    }
    catch (error) {
      if (!this.useFallback) {
        console.warn(`Native credential storage failed, using fallback: ${error}`)
        this._saveFallback(account, password)
      }
      else {
        throw error
      }
    }
  }

  get(account: string): string | null {
    try {
      if (!this.useFallback)
        return this._getNative(account)
      else return this._getFallback(account)
    }
    catch (error) {
      if (!this.useFallback) {
        console.warn(`Native credential retrieval failed, trying fallback: ${error}`)
        return this._getFallback(account)
      }
      return null
    }
  }

  delete(account: string) {
    try {
      if (!this.useFallback)
        this._deleteNative(account)
      else this._deleteFallback(account)
    }
    catch (error) {
      if (!this.useFallback) {
        console.warn(`Native credential deletion failed, trying fallback: ${error}`)
        this._deleteFallback(account)
      }
      else {
        throw error
      }
    }
  }

  private _isMac() { return process.platform === 'darwin' }
  private _isWindows() { return process.platform === 'win32' }
  private _isLinux() { return process.platform === 'linux' }

  private _saveNative(account: string, password: string) {
    if (this._isMac())
      this._saveMac(account, password)
    else if (this._isWindows())
      this._saveWindows(account, password)
    else if (this._isLinux())
      this._saveLinux(account, password)
    else throw new Error('Unsupported platform')
  }

  private _getNative(account: string): string | null {
    if (this._isMac())
      return this._getMac(account)
    else if (this._isWindows())
      return this._getWindows(account)
    else if (this._isLinux())
      return this._getLinux(account)
    else throw new Error('Unsupported platform')
  }

  private _deleteNative(account: string) {
    if (this._isMac())
      this._deleteMac(account)
    else if (this._isWindows())
      this._deleteWindows(account)
    else if (this._isLinux())
      this._deleteLinux(account)
    else throw new Error('Unsupported platform')
  }

  private _saveMac(account: string, password: string) {
    execSync(
      `security add-generic-password -a "${account}" -s "${this.service}" -w "${password}" -U`,
    )
  }

  private _getMac(account: string): string | null {
    try {
      return execSync(
        `security find-generic-password -a "${account}" -s "${this.service}" -w`,
        { encoding: 'utf8' },
      ).trim()
    }
    catch {
      return null
    }
  }

  private _deleteMac(account: string) {
    execSync(`security delete-generic-password -a "${account}" -s "${this.service}"`)
  }

  private _getFilePath(account: string) {
    const dir = path.join(process.env.APPDATA || '.', 'keyvault')
    if (!fs.existsSync(dir))
      fs.mkdirSync(dir, { recursive: true })
    return path.join(dir, `${this.service}-${account}.txt`)
  }

  private _saveWindows(account: string, password: string) {
    const file = this._getFilePath(account)
    const script = `
$secure = ConvertTo-SecureString '${password}' -AsPlainText -Force
$secure | ConvertFrom-SecureString | Set-Content '${file}'
`
    execSync(`pwsh -NoProfile -Command "${script.replace(/"/g, '\\"')}"`)
  }

  private _getWindows(account: string): string | null {
    const file = this._getFilePath(account)
    if (!fs.existsSync(file))
      return null

    const script = `
$encrypted = Get-Content '${file}'
$secure = ConvertTo-SecureString $encrypted
[System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
  [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
)
`
    try {
      return execSync(`pwsh -NoProfile -Command "${script.replace(/"/g, '\\"')}"`, {
        encoding: 'utf8',
      }).trim()
    }
    catch {
      return null
    }
  }

  private _deleteWindows(account: string) {
    const file = this._getFilePath(account)
    if (fs.existsSync(file))
      fs.unlinkSync(file)
  }

  private _hasSecretTool(): boolean {
    try {
      execSync('command -v secret-tool', { stdio: 'ignore' })
      return true
    }
    catch {
      return false
    }
  }

  private _saveLinux(account: string, password: string) {
    if (!this._hasSecretTool()) {
      throw new Error('secret-tool not available. Install libsecret-tools: sudo apt-get install libsecret-tools')
    }
    execSync(
      `secret-tool store --label="${this.service}" service "${this.service}" account "${account}"`,
      { input: password },
    )
  }

  private _getLinux(account: string): string | null {
    if (!this._hasSecretTool()) {
      throw new Error('secret-tool not available. Install libsecret-tools: sudo apt-get install libsecret-tools')
    }
    try {
      return execSync(
        `secret-tool lookup service "${this.service}" account "${account}"`,
        { encoding: 'utf8' },
      ).trim()
    }
    catch {
      return null
    }
  }

  private _deleteLinux(account: string) {
    if (!this._hasSecretTool()) {
      throw new Error('secret-tool not available. Install libsecret-tools: sudo apt-get install libsecret-tools')
    }
    execSync(`secret-tool clear service "${this.service}" account "${account}"`)
  }

  private _ensureCache() {
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true })
    }
    if (!existsSync(this.keyFile)) {
      writeFileSync(this.keyFile, crypto.randomBytes(32))
      try {
        chmodSync(this.keyFile, 0o600)
      }
      catch (error) {
        console.warn(`Could not set permissions on key file: ${error}`)
      }
    }
    if (!existsSync(this.cacheFile)) {
      writeFileSync(this.cacheFile, JSON.stringify({}))
      try {
        chmodSync(this.cacheFile, 0o600)
      }
      catch (error) {
        console.warn(`Could not set permissions on cache file: ${error}`)
      }
    }
  }

  private _readCache(): Record<string, string> {
    this._ensureCache()
    return JSON.parse(readFileSync(this.cacheFile, 'utf8'))
  }

  private _writeCache(obj: Record<string, string>) {
    this._ensureCache()
    writeFileSync(this.cacheFile, JSON.stringify(obj, null, 2))
  }

  private _encrypt(text: string): string {
    const key = readFileSync(this.keyFile)
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return Buffer.concat([iv, tag, enc]).toString('base64')
  }

  private _decrypt(data: string): string {
    const key = readFileSync(this.keyFile)
    const buf = Buffer.from(data, 'base64')
    const iv = buf.slice(0, 12)
    const tag = buf.slice(12, 28)
    const enc = buf.slice(28)
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8')
  }

  private _saveFallback(account: string, password: string) {
    const cache = this._readCache()
    cache[account] = this._encrypt(password)
    this._writeCache(cache)
  }

  private _getFallback(account: string): string | null {
    const cache = this._readCache()
    if (!cache[account])
      return null
    try {
      return this._decrypt(cache[account])
    }
    catch {
      return null
    }
  }

  private _deleteFallback(account: string) {
    const cache = this._readCache()
    delete cache[account]
    this._writeCache(cache)
  }
}
