# Vault Roadmap — Depth Layers

Pure x86-64 assembly CLI password vault. Zero dependencies. Single encrypted file.

---

## L1 — Working Vault (v1)

Core crypto + basic CLI. This is the foundation everything else builds on.

### Crypto primitives
- [x] SHA-256 (pure assembly, validated against NIST test vectors)
- [x] HMAC-SHA256
- [x] PBKDF2-SHA256 (100k iterations, 16-byte salt from /dev/urandom)
- [x] CTR mode encryption (SHA-256 keystream XOR)

### Vault file format
- [x] Magic header ("NYXVAULT")
- [x] Salt + iteration count + HMAC + entry count
- [x] Entries: cleartext name + encrypted blob (username, password, url, notes)

### Commands
- [x] `vault init` — create vault with master password
- [x] `vault add <name>` — add entry (prompts for fields)
- [x] `vault get <name>` — decrypt + print entry
- [x] `vault get <name> password` — print single field
- [x] `vault list` — list entry names (no decryption needed)
- [x] `vault gen <name> [length]` — generate random password + store
- [x] `vault rm <name>` — remove entry
- [x] `vault export` — dump all entries decrypted to stdout
- [x] `vault import <file>` — import from plaintext

### Terminal
- [x] Disable echo when reading master password (ioctl TCSETS)
- [x] Secure: zero master password from memory after use

---

## L2 — Usable Daily

Quality of life. This is what makes you actually reach for it instead of bw-get.

- [x] Clipboard integration — `vault clip github` (copies password via xclip)
- [x] Auto-clear clipboard after 30 seconds (fork + nanosleep + overwrite)
- [x] Fuzzy search — `vault get git` matches "github", "gitlab", "gitea"
- [x] Entry editing — `vault edit github` (re-prompts for fields, keeps unchanged ones)
- [x] `vault show <name>` — pretty-print all fields with labels + strength
- [x] `vault search <term>` — search across all entry names (case-insensitive substring)
- [x] `vault count` — show total entries
- [x] Password strength indicator on `vault add` / `vault show`
- [x] Configurable default password length (~/.vault/config) — `length=N`

---

## L3 — Serious Tool

Features that replace dedicated apps.

- [x] TOTP generation (RFC 6238)
  - SHA-1 implementation (validated against test vectors)
  - HMAC-SHA1
  - Base32 decode
  - 6-digit code from 30-second time window
  - `vault totp <name>` — print current code (verified against oathtool)
  - TOTP secret stored in notes field as base32
- [x] Multiple vaults — `vault --vault work get slack` (separate dirs per vault name)
- [x] Import from Bitwarden JSON export (`vault import --bitwarden export.json`)
  - Minimal JSON parser extracts name, username, password, uri, notes, totp
  - TOTP stored as notes when notes field is empty
- [x] Import from KeePass CSV (`vault import --keepass export.csv`)
  - Handles quoted CSV fields, skips header line
- [x] Encrypted backup — `vault backup` (copy to timestamped file)
- [x] Vault integrity check — `vault verify` (validate HMAC, detect corruption)

---

## L4 — Paranoid

For when the threat model is real.

- [x] mlock syscall — pin crypto buffers in RAM, prevent swap
- [x] Secure memory zeroing — overwrite all sensitive buffers on exit
- [x] Argon2id key derivation (memory-hard, resists GPU/ASIC attacks)
  - Blake2b hash function (12-round compression, variable output)
  - Argon2id: 16 MiB memory, 3 iterations, 1 lane
  - `vault --argon2 init` creates vault with Argon2id KDF (version 0x0002)
  - Backwards compatible: PBKDF2 vaults (version 0x0001) still work
  - mmap-based memory arena, auto-detected from vault file version
- [x] Key file support — `vault --keyfile /path/to/key get github`
  - Master password + key file = two-factor decryption
  - XOR SHA-256(keyfile) with PBKDF2 derived key
- [x] Auto-lock timeout — `vault unlock` caches key, auto-expires after 5 minutes
  - `vault lock` manually clears session
  - Session file at /tmp/.vault-session-<uid>, encrypted with random nonce
  - Background timer process auto-wipes after timeout
- [x] Emergency wipe — `vault wipe` securely destroys the vault file
  - 3-pass overwrite (zeros, 0xFF, random) + unlink
  - Requires typing "DESTROY" to confirm
- [x] Plausible deniability — `vault hidden <init|add|get|list|rm>`
  - Hidden vault section appended to main vault file
  - Different password derives different key
  - Hidden entries invisible to normal vault operations
  - Without hidden password, data indistinguishable from random padding

---

## Non-goals

- No GUI (this is CLI forever)
- No browser extension (pipe to clipboard instead)
- No cloud sync built-in (just sync the .enc file with rclone/Proton Drive)
- No server component (single file, single user)
