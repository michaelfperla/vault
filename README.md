# Vault

A CLI password manager written in pure x86-64 NASM assembly. Zero dependencies. No libc. Pure Linux syscalls. Single encrypted file.

**32 KB** static binary. **8000 lines** of assembly. Replaces a 300 MB Electron app.

## Install

```bash
git clone https://github.com/michaelfperla/vault.git
cd vault
make
make install    # copies to ~/.local/bin/vault
```

Requires: `nasm`, `ld` (GNU binutils), Linux x86-64.

## Quick Start

```bash
# Create your vault
vault init

# Add an entry
vault add github

# Get a password
vault get github password

# Copy password to clipboard (auto-clears in 30s)
vault clip github

# Generate a random password
vault gen aws 32

# List all entries
vault list

# Get a TOTP 2FA code
vault totp github
```

## All Commands

| Command | Description |
|---------|-------------|
| `vault init` | Create vault with master password |
| `vault add <name>` | Add entry (prompts for username, password, URL, notes, TOTP) |
| `vault get <name> [field]` | Get entry (field: username, password, url, notes, totp) |
| `vault show <name>` | Pretty-print entry with password strength |
| `vault list` | List all entry names |
| `vault search <term>` | Search entries (case-insensitive substring) |
| `vault count` | Show total entries |
| `vault gen <name> [len]` | Generate random password and store |
| `vault edit <name>` | Edit entry fields (enter to keep current) |
| `vault rm <name>` | Remove entry |
| `vault export` | Dump all entries (tab-separated) to stdout |
| `vault import <file>` | Import from tab-separated file |
| `vault import --bitwarden <file>` | Import from Bitwarden JSON export |
| `vault import --keepass <file>` | Import from KeePass CSV export |
| `vault totp <name>` | Generate TOTP 2FA code (RFC 6238) |
| `vault clip <name> [field]` | Copy field to clipboard, auto-clear 30s |
| `vault verify` | Verify vault integrity (HMAC check) |
| `vault backup` | Create timestamped backup |
| `vault unlock` | Cache key for 5 minutes (no repeated password prompts) |
| `vault lock` | Clear cached session |
| `vault wipe` | Securely destroy vault (3-pass overwrite) |
| `vault hidden <cmd>` | Plausible deniability (hidden vault within vault) |
| `vault migrate` | Migrate old entries to new format |

## Flags

| Flag | Description |
|------|-------------|
| `--keyfile <path>` | Two-factor: master password + key file |
| `--vault <name>` | Use named vault (`~/.vault-<name>/`) |
| `--argon2` | Use Argon2id KDF instead of PBKDF2 (for `init`) |

## Cryptography

All crypto implemented from scratch in assembly:

| Algorithm | Use |
|-----------|-----|
| SHA-256 | HMAC, PBKDF2, CTR keystream |
| SHA-1 | HMAC-SHA1 for TOTP |
| HMAC-SHA256 | Vault integrity verification |
| HMAC-SHA1 | TOTP code generation |
| PBKDF2-SHA256 | Key derivation (100k iterations) |
| Blake2b | Argon2id internal hash |
| Argon2id | Memory-hard key derivation (16 MiB, 3 passes) |
| CTR mode | Entry encryption (per-entry IV) |

SHA-256 validated against NIST test vectors. TOTP verified against `oathtool`.

## Vault File Format

```
[8 bytes]   magic: "NYXVAULT"
[2 bytes]   version: 0x0001 (PBKDF2) or 0x0002 (Argon2id)
[16 bytes]  salt
[4 bytes]   iteration count
[32 bytes]  HMAC-SHA256
[4 bytes]   entry count
[entries...]:
  [4 bytes]   name length
  [N bytes]   name (cleartext)
  [4 bytes]   encrypted data length
  [16 bytes]  IV
  [M bytes]   encrypted data (username\0password\0url\0notes\0totp\0)
```

## Security Features

- **No dependencies** — zero supply chain attack surface
- **mlock** — crypto buffers pinned in RAM, never swapped to disk
- **Memory zeroing** — master password and keys overwritten after use
- **HMAC verification** — wrong password or tampered vault detected immediately
- **Echo disabled** — master password not visible when typing
- **Key file** — optional two-factor (password + file)
- **Argon2id** — memory-hard KDF resists GPU/ASIC brute force
- **Secure wipe** — 3-pass overwrite (zeros, 0xFF, random) + unlink
- **Plausible deniability** — hidden vault with separate password, indistinguishable from random data

## Switching from Bitwarden

```bash
# 1. Export from Bitwarden (Settings > Export vault > JSON)
# 2. Create vault
vault init
# 3. Import (preserves notes AND TOTP secrets)
vault import --bitwarden bitwarden-export.json
# 4. Verify a few entries
vault show github
vault totp github
# 5. Delete the unencrypted export
rm bitwarden-export.json
```

## License

MIT
