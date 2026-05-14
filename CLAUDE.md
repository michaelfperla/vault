# vault — local password manager

Pure-asm encrypted credential store. Single file at `~/.vault/vault.enc` (Argon2id + ChaCha20-Poly1305). TOTP support. ~10k lines (`vault.asm`).

## Build

```
make                       # ./vault
make install               # cp to ~/.local/bin/vault
make clean
```

## CLI

```
vault init                       # create vault
vault add <name>                 # interactive entry creation
vault get <name> [field] [--raw] # username|password|url|notes|totp
vault show <name>                # full entry
vault list | search <q>
vault edit <name>
vault gen [opts]                 # generator
vault clip <name> [field]        # to clipboard
vault totp <name> [--raw]
vault verify | backup
vault import | export | migrate
vault hidden | wipe | lock | unlock

--keyfile <path>
--vault <name>          # named secondary vault
--vault-path <path>     # script/test override
```

`unlock` caches the derived key for 5 minutes at mode 0600.

## Structure

Single monolith. Key sections (grep by label):
- argv dispatch
- Argon2id KDF
- ChaCha20-Poly1305 AEAD (vendored, not phantom-linked)
- TOTP (HMAC-SHA1 + RFC 6238)
- vault file format (header, salt, nonce, sealed body)
- terminal IO (raw mode for passphrase entry)

Aux: `ROADMAP.md`, `LICENSE`, `tests/`.
