; ════════════════════════════════════════════════════════════════
; VAULT — CLI Password Manager
; x86-64 Linux // Pure Syscalls // No libc // Zero Dependencies
; ════════════════════════════════════════════════════════════════

BITS 64

; ── Syscall numbers ──────────────────────────────────────────
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_STAT        4
%define SYS_LSEEK       8
%define SYS_MMAP        9
%define SYS_IOCTL       16
%define SYS_EXIT        60
%define SYS_PRCTL       157
%define PR_SET_DUMPABLE 4

; Linux kernel keyring — replaces plaintext-key-on-disk session cache.
%define SYS_ADD_KEY     248
%define SYS_KEYCTL      250
%define KEYCTL_READ            11
%define KEYCTL_SET_TIMEOUT     15
%define KEYCTL_INVALIDATE      21
%define KEY_SPEC_SESSION_KEYRING 0xFFFFFFFD   ; -3 as unsigned u32 → kernel sign-extends
%define SYS_UNLINK      87
%define SYS_RENAME      82
%define SYS_MKDIR       83
%define SYS_GETDENTS64  217
%define SYS_GETRANDOM   318
%define SYS_FORK        57
%define SYS_EXECVE      59
%define SYS_NANOSLEEP   35
%define SYS_PIPE        22
%define SYS_DUP2        33
%define SYS_WAIT4       61
%define SYS_GETTIMEOFDAY  96
%define SYS_CLOCK_GETTIME 228
%define CLOCK_REALTIME     0
%define SYS_MLOCK      149
%define SYS_MUNLOCK    150
%define SYS_GETUID     102
%define SYS_SETSID     112
%define SYS_FSTAT      5

%define SESSION_TIMEOUT 60      ; 1 minute keyring expiry
%define SESSION_EXPIRY_OFFSET       0
%define SESSION_VAULT_HMAC_OFFSET   8
%define SESSION_KEYFILE_FLAG_OFFSET 40
%define SESSION_KEYFILE_HASH_OFFSET 41
%define SESSION_SERIAL_OFFSET       73
%define SESSION_FILE_SIZE           77      ; v2 stub — was 105 with key bytes
; Session file v2 stores:
;   expiry(8) + vault_hmac(32) + keyfile_flag(1) + keyfile_hash(32) + keyring_serial(4)
; The derived_key itself lives in the Linux kernel session keyring under
; description "vault:session"; the stub only holds the serial number that
; lets us fetch it back. File-disclosure attacks no longer leak the key.

; ── File flags ───────────────────────────────────────────────
%define O_RDONLY    0
%define O_WRONLY    1
%define O_RDWR     2
%define O_CREAT    0x40
%define O_TRUNC    0x200
%define O_EXCL     0x80

%define STDIN   0
%define STDOUT  1
%define STDERR  2

; ── Terminal ─────────────────────────────────────────────────
%define TCGETS  0x5401
%define TCSETS  0x5402
%define ECHO    0x08
%define ICANON  0x02

; ── Vault constants ──────────────────────────────────────────
%define VAULT_VERSION   0x0001
%define PBKDF2_ITER     100000
%define SALT_LEN        16
%define IV_LEN          16
%define HMAC_LEN        32
%define KEY_LEN         32
%define SHA256_DIGEST   32
%define SHA256_BLOCK    64
%define MAX_ENTRIES     256
%define MAX_NAME_LEN    64
%define MAX_FIELD_LEN   256
%define MAX_ENTRY_DATA  1024
%define BUF_SIZE        65536

; ════════════════════════════════════════════════════════════════
section .data
; ════════════════════════════════════════════════════════════════

; ── SHA-256 round constants (K) ──────────────────────────────
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

; ── SHA-256 initial hash values (H) ─────────────────────────
sha256_h_init:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

; ── SHA-1 round constants ────────────────────────────────────
sha1_k:
    dd 0x5a827999           ; rounds 0-19
    dd 0x6ed9eba1           ; rounds 20-39
    dd 0x8f1bbcdc           ; rounds 40-59
    dd 0xca62c1d6           ; rounds 60-79

; ── SHA-1 initial hash values ────────────────────────────────
sha1_h_init:
    dd 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0

; ── Blake2b IV (64-bit words, little-endian) ─────────────────
blake2b_iv:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
    dq 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f
    dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

; ── Blake2b sigma (message schedule for 12 rounds) ──────────
blake2b_sigma:
    db  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
    db 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3
    db 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4
    db  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8
    db  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13
    db  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9
    db 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11
    db 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10
    db  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5
    db 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
    db  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
    db 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3

; ── Argon2 parameters ────────────────────────────────────────
%define ARGON2_MEMORY   16384   ; 16 MiB in 1 KiB blocks
%define ARGON2_ITER     3       ; time cost
%define ARGON2_LANES    1       ; parallelism
%define ARGON2_TAGLEN   32
%define ARGON2_BLOCK    1024    ; bytes per block
%define ARGON2_TYPE_ID  2       ; Argon2id
%define ARGON2_VERSION  0x13    ; v1.3
%define MAP_ANONYMOUS   0x20
%define MAP_PRIVATE     0x02
%define PROT_READ       0x01
%define PROT_WRITE      0x02
%define SYS_MUNMAP      11

; ── Base32 alphabet ──────────────────────────────────────────
base32_alpha: db "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

; ── Magic ────────────────────────────────────────────────────
vault_magic: db "NYXVAULT", 0

; ── Vault file path ──────────────────────────────────────────
vault_dir:      db 0      ; will be built at runtime from HOME
vault_dir_tpl:  db "/.vault", 0
vault_file_tpl: db "/.vault/vault.enc", 0
vault_conf_tpl: db "/.vault/config", 0
conf_key_len:   db "length=", 0
conf_key_vault: db "vault=", 0

; ── Command strings ──────────────────────────────────────────
cmd_init:       db "init", 0
cmd_add:        db "add", 0
cmd_get:        db "get", 0
cmd_list:       db "list", 0
cmd_gen:        db "gen", 0
cmd_rm:         db "rm", 0
cmd_export:     db "export", 0
cmd_import:     db "import", 0
cmd_show:       db "show", 0
cmd_search:     db "search", 0
cmd_count:      db "count", 0
cmd_edit:       db "edit", 0
cmd_clip:       db "clip", 0
cmd_totp:       db "totp", 0
cmd_verify:     db "verify", 0
cmd_backup:     db "backup", 0
cmd_wipe:       db "wipe", 0
cmd_unlock:     db "unlock", 0
cmd_lock:       db "lock", 0
cmd_hidden:     db "hidden", 0
cmd_migrate:    db "migrate", 0
cmd_help:       db "help", 0
cmd_status:     db "status", 0
msg_migrate_ok: db "Vault migrated to new format (with TOTP field).", 10, 0
msg_migrating:  db "Migrating entry: ", 0
cmd_test_sha:   db "test-sha256", 0
cmd_test_cc:    db "test-chacha20", 0

; ── Field prompts ────────────────────────────────────────────
prompt_master:      db "Master password: ", 0
prompt_confirm:     db "Confirm password: ", 0
prompt_username:    db "Username: ", 0
prompt_password:    db "Password: ", 0
prompt_url:         db "URL: ", 0
prompt_notes:       db "Notes: ", 0
prompt_totp:        db "TOTP secret (base32, or empty): ", 0
prompt_edit_hint:   db " (enter to keep, or new value): ", 0
prompt_cur_user:    db "  Username [", 0
prompt_cur_pass:    db "  Password [", 0
prompt_cur_url:     db "  URL [", 0
prompt_cur_note:    db "  Notes [", 0
prompt_cur_totp:    db "  TOTP [", 0
prompt_close:       db "]: ", 0
prompt_empty:       db 0

; ── Messages ─────────────────────────────────────────────────
msg_usage:      db "Vault — local terminal password manager", 10, 10
                db "Usage:", 10
                db "  vault [--keyfile <path>] [--vault <name>] <command> [args]", 10
                db "  vault [--vault-path <path>] <command> [args]", 10, 10
                db "Getting Started:", 10
                db "  init, add, get, clip, backup", 10, 10
                db "Daily Use:", 10
                db "  add, get, show, list, search, edit, gen, clip, totp", 10, 10
                db "Safety and Recovery:", 10
                db "  verify, backup, help", 10, 10
                db "Import / Export:", 10
                db "  import, export, migrate", 10, 10
                db "Advanced / Dangerous:", 10
                db "  hidden, wipe, lock, unlock", 10, 10
                db "Notes:", 10
                db "  unlock caches the derived key for 5 minutes (mode 0600).", 10
                db "  use --vault-path to test or script without touching ~/.vault.", 10, 0
msg_help_init:  db "vault init", 10
                db "  Create a new vault at the selected path.", 10
                db "  Example: vault --vault-path /tmp/demo.enc init", 10
                db "  Non-interactive: printf 'secret\n' | vault init --password-stdin", 10, 0
msg_help_add:   db "vault add <name>", 10
                db "  Add an entry interactively or with explicit field flags.", 10
                db "  Example: vault add github", 10
                db "  Scripted: printf 'master\nentrypass\n' | vault add github --username alice --password-stdin --url https://example.com", 10, 0
msg_help_get:   db "vault get <name> [field]", 10
                db "  Retrieve one field or print the whole entry.", 10
                db "  Example: vault get github password", 10
                db "  Tip: use 'vault search <term>' if you forgot the exact name.", 10, 0
msg_help_backup: db "vault backup", 10
                 db "  Create a timestamped backup next to the current vault file.", 10
                 db "  Example: vault backup", 10, 0
msg_help_verify: db "vault verify", 10
                 db "  Recompute and verify the vault HMAC before risky operations.", 10
                 db "  Example: vault verify", 10, 0
msg_help_unknown: db "No detailed help for that topic yet. Try: init, add, get, backup, verify.", 10, 0
msg_output_opt: db "Error: unsupported output option. Use --raw or --json.", 10, 0
msg_output_conflict: db "Error: choose only one output mode: --raw or --json.", 10, 0
msg_init_ok:    db "Vault created at ~/.vault/vault.enc", 10, 0
msg_init_exist: db "Error: vault already exists. Delete ~/.vault/vault.enc to reinitialize.", 10, 0
msg_no_vault:   db "Error: no vault found at the selected path.", 10
                db "Next: run 'vault init' or use --vault-path/--vault to select the right vault.", 10, 0
msg_mismatch:   db "Error: passwords do not match.", 10, 0
msg_added:      db "Entry added.", 10, 0
msg_removed:    db "Entry removed.", 10, 0
msg_not_found:  db "Error: entry not found.", 10
                db "Next: run 'vault list' or 'vault search <term>' to find the entry name.", 10, 0
msg_exists:     db "Error: entry already exists.", 10, 0
msg_no_name:    db "Error: name required.", 10, 0
msg_init_opt:   db "Error: unsupported init option. Try 'vault help init'.", 10, 0
msg_unknown_cmd: db "Error: unknown command. Run 'vault' with no arguments for usage.", 10, 0

; ── status command strings ───────────────────────────────────
status_label_path:    db "path:            ", 0
status_label_exists:  db "exists:          ", 0
status_label_version: db "version:         ", 0
status_label_kdf:     db "kdf:             ", 0
status_label_entries: db "entries:         ", 0
status_label_session: db "session_active:  ", 0
status_yes:           db "yes", 10, 0
status_no:            db "no", 10, 0
status_kdf_pbkdf2:    db "pbkdf2-sha256", 10, 0
status_kdf_argon2:    db "argon2id", 10, 0
status_kdf_unknown:   db "unknown", 10, 0
status_v1:            db "1 (PBKDF2, legacy)", 10, 0
status_v2:            db "2 (Argon2id, legacy header)", 10, 0
status_v3:            db "3 (Argon2id + authenticated header)", 10, 0
status_v0:            db "0", 10, 0

; JSON keys for status
json_status_path:     db '"path":"', 0
json_status_exists:   db '","exists":', 0
json_status_version:  db ',"version":', 0
json_status_kdf:      db ',"kdf":"', 0
json_status_entries:  db '","entries":', 0
json_status_session:  db ',"session_active":', 0
json_true_close:      db "true}", 10, 0
json_false_close:     db "false}", 10, 0
json_obj_close:       db "}", 10, 0
json_true_word:       db "true", 0
json_false_word:      db "false", 0
json_kdf_pbkdf2_word: db 'pbkdf2-sha256', 0
json_kdf_argon2_word: db 'argon2id', 0
json_kdf_unknown_word: db 'unknown', 0
msg_add_opt:    db "Error: unsupported add option. Try 'vault help add'.", 10, 0
msg_opt_value:  db "Error: option requires a value.", 10, 0
msg_imported:   db " entries imported.", 10, 0
msg_empty:      db "Vault is empty.", 10, 0
msg_generated:  db "Generated password stored.", 10, 0
msg_hmac_fail:  db "Error: vault could not be opened.", 10
                db "Likely causes: wrong password, wrong key file, or corrupted vault data.", 10
                db "Next: retry credentials, verify the selected path, or restore from backup.", 10, 0
msg_updated:    db "Entry updated.", 10, 0
msg_entries:    db " entries", 10, 0
msg_no_match:   db "No matches found.", 10, 0
msg_copied:     db "Copied to clipboard. Auto-clearing in 30s.", 10, 0
msg_cleared:    db "Clipboard cleared.", 10, 0
msg_no_xclip:   db "Error: xclip not found.", 10, 0
msg_strength_weak:   db "  strength: weak", 10, 0
msg_strength_fair:   db "  strength: fair", 10, 0
msg_strength_good:   db "  strength: good", 10, 0
msg_strength_strong: db "  strength: strong", 10, 0
msg_sep:        db "────────────────────────────────", 10, 0
msg_verify_ok:  db "Vault integrity verified. HMAC OK.", 10, 0
msg_backup_ok:  db "Backup created: ", 0
msg_totp_code:  db "TOTP: ", 0
msg_totp_none:  db "Error: no TOTP secret stored for this entry.", 10, 0
msg_totp_hint:  db "Next: run 'vault edit <name>' and add the TOTP secret in the dedicated TOTP field.", 10, 0
msg_wipe_confirm: db "Type 'DESTROY' to permanently wipe the vault: ", 0
msg_wipe_ok:    db "Vault securely wiped.", 10, 0
msg_wipe_abort: db "Wipe aborted.", 10, 0
msg_mlock_ok:   db 0    ; silent
wipe_confirm:   db "DESTROY", 0
keyfile_flag:   db "--keyfile", 0
argon2_flag:    db "--argon2", 0          ; preserved for backward compat (no-op since v3 default)
pbkdf2_flag:    db "--pbkdf2", 0          ; opt back into legacy v1 PBKDF2 KDF
upgrade_kdf_flag: db "--upgrade-kdf", 0   ; vault migrate --upgrade-kdf
v4_flag_str:    db "--v4", 0              ; opt into v4 (ChaCha20-Poly1305 AEAD) on init
upgrade_aead_flag: db "--upgrade-aead", 0 ; vault migrate --upgrade-aead (v3 → v4)
msg_migrate_already_v3: db "Vault is already at version 3. Nothing to upgrade.", 10, 0
msg_migrate_upgrade_ok: db "Vault upgraded to v3 (Argon2id + authenticated header).", 10, 0
msg_migrate_upgrade_aead_ok: db "Vault upgraded to v4 (ChaCha20-Poly1305 AEAD).", 10, 0
msg_already_v4: db "Vault is already v4.", 10, 0
msg_hidden_v4_unsupported: db "Error: vault contains a hidden section; v4 migration with hidden sections is not yet supported.", 10, 0
msg_hidden_v4_blocked: db "Error: hidden vault operations are not supported on v4 vaults.", 10, 0
err_no_random: db "FATAL: kernel random source returned short or failed; aborting to avoid weak crypto.", 10
ERR_NO_RANDOM_LEN equ $ - err_no_random
msg_migrate_too_big:    db "Error: vault too large to upgrade in-place (>64 KiB entries).", 10, 0
password_stdin_flag: db "--password-stdin", 0
username_flag:  db "--username", 0
url_flag:       db "--url", 0
notes_flag:     db "--notes", 0
totp_flag:      db "--totp", 0
raw_flag:       db "--raw", 0
json_flag:      db "--json", 0
exact_flag:     db "--exact", 0
msg_argon2_init: db "Vault created with Argon2id (16 MiB, 3 iterations).", 10, 0
msg_argon2_kdf:  db 0   ; silent marker

%define VAULT_VERSION_PBKDF2 0x0001     ; legacy: PBKDF2 + HMAC over [62..end]
%define VAULT_VERSION_ARGON2 0x0002     ; legacy: Argon2id + HMAC over [62..end]
%define VAULT_VERSION_V3     0x0003     ; Argon2id + HMAC over full file (slot zeroed)
%define VAULT_VERSION_V4     0x0004     ; Argon2id + ChaCha20-Poly1305 AEAD (header=AAD)
%define V4_HEADER_LEN        62         ; header bytes used as AAD (magic+ver+salt+iter+nonce+reserved)
%define V4_TAG_LEN           16         ; Poly1305 tag length
%define V4_NONCE_LEN         12         ; ChaCha20 nonce length
%define V4_NONCE_OFFSET      30         ; offset of nonce within header
%define V4_RESERVED_OFFSET   42         ; offset of zero-reserved bytes
%define V4_RESERVED_LEN      20         ; size of zero-reserved region
vault_flag:     db "--vault", 0
vault_path_flag: db "--vault-path", 0
vault_dir_fmt:  db "/.vault-", 0     ; HOME + /.vault-<name>/vault.enc
msg_keyfile_loaded: db "Key file loaded.", 10, 0
field_totp:     db "totp", 0
label_totp:     db "  totp: ", 0
backup_suffix:  db ".bak.", 0
msg_newline:    db 10, 0

; ── Session/lock messages ────────────────────────────────────
msg_unlocked:   db "Vault unlocked. Session expires in 5 minutes.", 10, 0
msg_locked:     db "Vault locked. Session cleared.", 10, 0
msg_no_session: db "No active session.", 10, 0
msg_session_active: db "Session active. Using cached key.", 10, 0
msg_session_write_fail: db "Error: could not write session cache.", 10, 0
msg_keyfile_required: db "Error: key file missing, unreadable, or empty.", 10
                      db "Next: verify the --keyfile path and file contents, then retry.", 10, 0
session_path_prefix: db "/tmp/.vault-session-", 0

; Linux keyring strings
key_type_user:  db "user", 0
key_desc_prefix: db "vault:session:", 0    ; followed by 16 hex chars of vault_hmac
err_msg_keyring: db "kernel keyring unavailable", 0
err_code_keyring: db "keyring_unavailable", 0
msg_keyring_unavailable: db "Error: kernel keyring unavailable. Run from a logged-in session, or operate without `unlock` caching.", 10, 0

; ── Hidden vault messages ────────────────────────────────────
msg_hidden_init:    db "Hidden vault initialized within main vault.", 10, 0
msg_hidden_pw:      db "Hidden password: ", 0
msg_hidden_add:     db "Entry added to hidden vault.", 10, 0
msg_hidden_usage:   db "Usage: vault hidden <init|add|get|list|rm> [args]", 10, 0
msg_hidden_empty:   db "Hidden vault is empty.", 10, 0
hidden_marker:  db "NYXHIDE", 0

json_ok_true:   db '{', '"', 'o', 'k', '"', ':', 't', 'r', 'u', 'e', '}', 10, 0
json_empty_arr: db "[]", 10, 0
json_key_count: db "count", 0
json_key_code:  db "code", 0
msg_ok_raw:     db "ok", 10, 0

; ── JSON error envelope fragments ────────────────────────────
json_err_prefix:   db '{"ok":false,"code":"', 0
json_err_middle:   db '","error":"', 0
json_err_suffix:   db '"}', 10, 0

; ── Error code slugs (machine-stable) ────────────────────────
err_code_no_vault:      db "no_vault", 0
err_code_need_name:     db "need_name", 0
err_code_not_found:     db "not_found", 0
err_code_entry_exists:  db "entry_exists", 0
err_code_bad_output:    db "bad_output_flag", 0
err_code_output_conflict: db "output_flag_conflict", 0
err_code_unknown_cmd:   db "unknown_command", 0
err_code_auth_failed:   db "auth_failed", 0
err_code_pw_mismatch:   db "password_mismatch", 0
err_code_vault_exists:  db "vault_exists", 0
err_code_missing_value: db "missing_value", 0
err_code_no_xclip:      db "no_xclip", 0
err_code_no_totp:       db "no_totp", 0
err_code_session_write: db "session_write_fail", 0
err_code_keyfile:       db "keyfile_required", 0
err_code_bad_option:    db "bad_option", 0
err_code_list_empty:    db "vault_empty", 0
err_code_no_session:    db "no_session", 0

; Short error messages used inside the JSON envelope (no trailing newline, no hint text)
err_msg_no_vault:      db "no vault found at the selected path", 0
err_msg_need_name:     db "name required", 0
err_msg_not_found:     db "entry not found", 0
err_msg_entry_exists:  db "entry already exists", 0
err_msg_bad_output:    db "unsupported output option", 0
err_msg_output_conflict: db "conflicting output modes (--raw and --json)", 0
err_msg_unknown_cmd:   db "unknown command", 0
err_msg_auth_failed:   db "vault could not be opened (wrong password, key file, or corrupted data)", 0
err_msg_pw_mismatch:   db "passwords do not match", 0
err_msg_vault_exists:  db "vault already exists at the selected path", 0
err_msg_missing_value: db "option requires a value", 0
err_msg_no_xclip:      db "xclip not found", 0
err_msg_no_totp:       db "no TOTP secret stored for this entry", 0
err_msg_session_write: db "could not write session cache", 0
err_msg_keyfile:       db "key file missing, unreadable, or empty", 0
err_msg_list_empty:    db "vault is empty", 0
err_msg_no_session:    db "no active session", 0
err_msg_bad_option:    db "unsupported option", 0

json_escape_quote: db 92, 34, 0
json_escape_bs:    db 92, 92, 0
json_escape_n:     db 92, 'n', 0
json_escape_r:     db 92, 'r', 0
json_escape_t:     db 92, 't', 0

; Hidden vault sub-commands
hid_init_str:   db "init", 0
hid_add_str:    db "add", 0
hid_get_str:    db "get", 0
hid_list_str:   db "list", 0
hid_rm_str:     db "rm", 0

; ── Import format flags ──────────────────────────────────────
import_bw_flag: db "--bitwarden", 0
import_kp_flag: db "--keepass", 0
; JSON field keys for Bitwarden
json_name:      db '"name"', 0
json_username:  db '"username"', 0
json_password:  db '"password"', 0
json_uri:       db '"uri"', 0
json_notes:     db '"notes"', 0
json_totp:      db '"totp"', 0

; ── SHA-256 test data ────────────────────────────────────────
test_sha_hdr:   db "=== SHA-256 Test Vectors ===", 10, 0
test_empty_msg: db "SHA256(''):  ", 0
test_abc_msg:   db "SHA256('abc'):  ", 0
test_hello_msg: db "SHA256('hello'):  ", 0
test_str_abc:   db "abc"
test_str_hello: db "hello"
test_pass:      db " [PASS]", 10, 0
test_fail:      db " [FAIL]", 10, 0
test_expect:    db "  expect: ", 0

; Expected SHA-256 hashes (raw bytes, big-endian)
expected_empty:
    db 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
    db 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
    db 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
    db 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

expected_abc:
    db 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
    db 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
    db 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
    db 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad

expected_hello:
    db 0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e
    db 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e
    db 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e
    db 0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24

; ── ChaCha20 test data (RFC 8439 §2.3.2) ─────────────────────
test_cc_hdr:    db "=== ChaCha20 Test Vectors (RFC 8439) ===", 10, 0
test_cc_232:    db "Block §2.3.2:    ", 0

; RFC 8439 §2.3.2 inputs:
; key   = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
;         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
; nonce = 00 00 00 09 00 00 00 4a 00 00 00 00
; ctr   = 1
cc_232_key:
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
cc_232_nonce:
    db 0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a
    db 0x00,0x00,0x00,0x00

; Expected serialized block (RFC 8439 §2.3.2):
cc_232_expected:
    db 0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15
    db 0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4
    db 0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03
    db 0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e
    db 0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09
    db 0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2
    db 0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9
    db 0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e

; ── Poly1305 test data (RFC 8439 §2.5.2) ─────────────────────
test_p_252:     db "Poly1305 §2.5.2: ", 0
p_252_key:
    db 0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33
    db 0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8
    db 0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd
    db 0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
p_252_msg:
    db "Cryptographic Forum Research Group"
P_252_MSG_LEN equ $ - p_252_msg
p_252_expected:
    db 0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6
    db 0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9

; ── AEAD test data (RFC 8439 §2.8.2) ─────────────────────────
test_a_282:     db "AEAD §2.8.2 tag: ", 0
test_a_rt:      db "AEAD roundtrip:  ", 0
test_a_tp:      db "AEAD tamper rej: ", 0
a_282_key:
    db 0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87
    db 0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f
    db 0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97
    db 0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
a_282_nonce:
    db 0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43
    db 0x44,0x45,0x46,0x47
a_282_aad:
    db 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3
    db 0xc4,0xc5,0xc6,0xc7
A_282_AAD_LEN equ $ - a_282_aad
a_282_pt:
    db "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
A_282_PT_LEN equ $ - a_282_pt
a_282_tag:
    db 0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a
    db 0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91

test_sha1_abc_msg: db "SHA1('abc'):  ", 0
expected_sha1_abc:
    db 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a
    db 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c
    db 0x9c, 0xd0, 0xd8, 0x9d

hex_chars: db "0123456789abcdef"

; ── Password generation charset ──────────────────────────────
gen_charset: db "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+", 0
gen_charset_len equ 78
gen_default_len equ 24

; ── Field labels for display ─────────────────────────────────
label_name:     db "  name: ", 0
label_user:     db "  user: ", 0
label_pass:     db "  pass: ", 0
label_url:      db "  url:  ", 0
label_notes:    db "  note: ", 0
label_totp2:    db "  totp: ", 0
field_username: db "username", 0
field_password: db "password", 0
field_url:      db "url", 0
field_notes:    db "notes", 0

; ── Clipboard tool paths ─────────────────────────────────────
xclip_path:     db "/usr/bin/xclip", 0
xclip_arg0:     db "xclip", 0
xclip_arg1:     db "-selection", 0
xclip_arg2:     db "clipboard", 0
xsel_path:      db "/usr/bin/xsel", 0
xsel_arg0:      db "xsel", 0
xsel_arg1:      db "--clipboard", 0
xsel_arg2:      db "--input", 0

section .data
align 8
xclip_argv:     dq xclip_arg0, xclip_arg1, xclip_arg2, 0
xsel_argv:      dq xsel_arg0, xsel_arg1, xsel_arg2, 0

; ════════════════════════════════════════════════════════════════
section .bss
; ════════════════════════════════════════════════════════════════

; ── SHA-256 working state ────────────────────────────────────
sha256_state:   resd 8          ; current hash state H0..H7
sha256_block:   resb 64         ; message block buffer
sha256_w:       resd 64         ; message schedule W[0..63]
sha256_bitlen:  resq 1          ; total message bit length
sha256_buflen:  resd 1          ; bytes buffered in sha256_block

; ── SHA-1 working state ──────────────────────────────────────
sha1_state:     resd 5          ; current hash state H0..H4
sha1_block:     resb 64         ; message block buffer
sha1_w:         resd 80         ; message schedule W[0..79]
sha1_bitlen:    resq 1          ; total message bit length
sha1_buflen:    resd 1          ; bytes buffered

; ── TOTP working space ───────────────────────────────────────
totp_secret:    resb 64         ; decoded TOTP secret (raw bytes)
totp_hmac_out:  resb 20         ; HMAC-SHA1 output
totp_counter:   resb 8          ; 8-byte big-endian counter
backup_path:    resb 512        ; backup file path
keyfile_buf:    resb 256        ; keyfile contents
keyfile_hash:   resb 32         ; SHA-256 of keyfile
keyfile_path:   resq 1          ; pointer to keyfile path (0 = none)
keyfile_active: resb 1          ; 1 if keyfile in use
wipe_input:     resb 32         ; wipe confirmation input
config_path:    resb 512        ; ~/.vault/config path
config_buf:     resb 512        ; config file contents
config_gen_len: resd 1          ; configured default password length
vault_name:     resb 64         ; --vault name (for multi-vault)

; ── Session management ───────────────────────────────────────
session_path:   resb 128        ; /tmp/.vault-session-<uid>-<hex>
session_buf:    resb 128        ; session file buffer
old_session_path: resb 128      ; pre-save snapshot of session path (for cleanup after save changes the HMAC slot)
session_active: resb 1          ; 1 if session key loaded from file

; ── Hidden vault ─────────────────────────────────────────────
hidden_pw:      resb 256        ; hidden vault password
hidden_pw2:     resb 256        ; confirm
hidden_key:     resb 32         ; derived key for hidden vault
hidden_salt:    resb 16         ; hidden vault salt
hidden_hmac:    resb 32         ; hidden vault HMAC
hidden_buf:     resb BUF_SIZE   ; hidden vault data buffer
hidden_section_ptr: resq 1      ; pointer to entry count in hidden section

; ── Blake2b working state ────────────────────────────────────
b2b_h:          resq 8          ; hash state
b2b_buf:        resb 128        ; message buffer
b2b_buflen:     resd 1          ; bytes in buffer
b2b_counter:    resq 2          ; byte counter (128-bit)
b2b_outlen:     resd 1          ; desired output length
b2b_v:          resq 16         ; working vector for compress
b2b_m:          resq 16         ; message words for compress

; ── Argon2 working space ─────────────────────────────────────
argon2_arena:   resq 1          ; mmap'd memory pointer
argon2_h0:      resb 64         ; initial 64-byte hash H0
argon2_tmp_block: resb ARGON2_BLOCK  ; temp block for G function
argon2_r_block:   resb ARGON2_BLOCK  ; R block for G
argon2_use_argon2: resb 1       ; 1 if vault uses argon2id

; ── HMAC working space ───────────────────────────────────────
hmac_ipad:      resb 64         ; key XOR ipad
hmac_opad:      resb 64         ; key XOR opad
hmac_inner:     resb 32         ; inner hash result
hmac_key_buf:   resb 64         ; padded key

; ── PBKDF2 working space ────────────────────────────────────
pbkdf2_u:       resb 32         ; U_i
pbkdf2_t:       resb 32         ; T (accumulated XOR)
pbkdf2_salt_i:  resb 80         ; salt || INT(i)

; ── Derived key ──────────────────────────────────────────────
derived_key:    resb 32

; ── General buffers ──────────────────────────────────────────
buf:            resb BUF_SIZE
input_buf:      resb 512
master_pw:      resb 256
master_pw2:     resb 256
init_pw_from_stdin: resb 1
output_raw:     resb 1
output_json:    resb 1
status_numbuf:  resb 32          ; scratch for itoa in do_status
saved_hmac_slot: resb 32         ; scratch for v3 HMAC verify (preserve-zero-restore)
entry_name:     resb MAX_NAME_LEN
entry_user:     resb MAX_FIELD_LEN
entry_pass:     resb MAX_FIELD_LEN
entry_url:      resb MAX_FIELD_LEN
entry_notes:    resb MAX_FIELD_LEN
entry_totp:     resb MAX_FIELD_LEN
add_user_provided: resb 1
add_url_provided:  resb 1
add_notes_provided: resb 1
add_totp_provided: resb 1
add_pw_from_stdin: resb 1
entry_data:     resb MAX_ENTRY_DATA
crypt_buf:      resb MAX_ENTRY_DATA
migrate_old_entries:    resb 65536      ; saved ciphertext section during KDF upgrade
migrate_old_entries_size: resq 1
migrate_old_entry_count: resd 1
migrate_old_key:        resb 32         ; key derived with old KDF
migrate_new_key:        resb 32         ; key derived with new KDF
migrate_cursor:         resq 1          ; walking pointer through migrate_old_entries
migrate_remaining:      resd 1          ; entries left to re-encrypt
keyring_desc:           resb 64         ; "vault:session:<16 hex>" + null
hex_out:        resb 128
edit_buf:       resb MAX_FIELD_LEN
search_term:    resb MAX_NAME_LEN
clip_pipe:      resb 512

; ── Vault file data ──────────────────────────────────────────
vault_path:     resb 512
vault_salt:     resb SALT_LEN
vault_hmac:     resb HMAC_LEN
vault_buf:      resb BUF_SIZE
vault_tmp_path: resb 512

; ── Terminal state ───────────────────────────────────────────
old_termios:    resb 60
new_termios:    resb 60

; ── Misc ─────────────────────────────────────────────────────
vault_file_size: resq 1
argc:           resq 1
argv:           resq 1
numbuf:         resb 32
iv_buf:         resb IV_LEN
keystream_blk:  resb 32
ctr_input:      resb 32         ; IV(16) + counter(4) for CTR mode

; ── ChaCha20 working space (RFC 8439) ────────────────────────
chacha_state:   resd 16         ; initial state: const(4) || key(8) || ctr(1) || nonce(3)
chacha_work:    resd 16         ; working state, mutated by 20 rounds
chacha_block:   resb 64         ; serialized keystream block output

; ── Poly1305 working space (RFC 8439 §2.5) ───────────────────
poly_r:         resq 2          ; clamped 128-bit r (LE)
poly_s:         resq 2          ; pad value s (LE)
poly_h:         resq 3          ; accumulator h0, h1, h2 (radix 2^64, h2 small)
poly_buf:       resb 16         ; partial-block padding buffer
poly_tag:       resb 16         ; tag output scratch
poly_otk:       resb 32         ; one-time Poly1305 key (AEAD)
poly_lens:      resb 16         ; AEAD length block (aad_len || ct_len, LE u64)
aead_scratch:   resb 128        ; AEAD test scratch (plaintext copy)
g_vault_version: resw 1         ; set by open_vault / init: 1/2/3/4
v4_flag:        resb 1          ; CLI flag: 1 = --v4 requested on init

; ════════════════════════════════════════════════════════════════
section .text
global _start
; ════════════════════════════════════════════════════════════════

_start:
    ; Save argc, argv
    mov rax, [rsp]          ; argc
    mov [rel argc], rax
    lea rax, [rsp+8]        ; argv[0]
    mov [rel argv], rax

    ; Disable coredumps and ptrace-attach: prctl(PR_SET_DUMPABLE, 0, 0, 0, 0).
    ; Defeats `gcore`, core-dump-on-crash key exfil, and same-uid ptrace inspection
    ; of master_pw / derived_key while they're live in memory.
    mov edi, PR_SET_DUMPABLE
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, SYS_PRCTL
    syscall

    ; Build vault path from HOME env
    call build_vault_path

    ; Check argc >= 2
    mov rax, [rel argc]
    cmp rax, 2
    jl show_usage

    ; KDF selection: Argon2id is the default since hardening leap.
    ; --pbkdf2 opts back into the legacy KDF. --argon2 is kept as a no-op
    ; alias so older scripts don't break.
    mov byte [rel argon2_use_argon2], 1
    mov rax, [rel argv]
    mov rdi, [rax+8]
    lea rsi, [rel argon2_flag]
    call strcmp
    test eax, eax
    jnz .check_pbkdf2_flag
    ; explicit --argon2: still default, just shift it off argv
    mov rax, [rel argc]
    dec rax
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 8
    mov [rel argv], rax
    jmp .no_kdf_flag
.check_pbkdf2_flag:
    mov rax, [rel argv]
    mov rdi, [rax+8]
    lea rsi, [rel pbkdf2_flag]
    call strcmp
    test eax, eax
    jnz .no_kdf_flag
    mov byte [rel argon2_use_argon2], 0
    mov rax, [rel argc]
    dec rax
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 8
    mov [rel argv], rax
.no_kdf_flag:
.no_argon2_flag:

    ; Check for --keyfile flag: vault --keyfile <path> <command> [args]
    mov byte [rel keyfile_active], 0
    mov rax, [rel argv]
    mov rdi, [rax+8]        ; argv[1]
    lea rsi, [rel keyfile_flag]
    call strcmp
    test eax, eax
    jnz .no_keyfile

    ; --keyfile mode: need argc >= 4 (prog --keyfile path cmd)
    mov rax, [rel argc]
    cmp rax, 4
    jl show_usage

    ; Save keyfile path
    mov rax, [rel argv]
    mov rdi, [rax+16]       ; argv[2] = keyfile path
    mov [rel keyfile_path], rdi

    ; Shift argv: make argv[3] look like argv[1]
    ; We do this by adjusting argc and argv pointer
    mov rax, [rel argc]
    sub rax, 2
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 16             ; skip 2 args
    mov [rel argv], rax
    mov byte [rel keyfile_active], 1
.no_keyfile:

    ; Check for --vault flag: vault --vault <name> <command> [args]
    mov rax, [rel argv]
    mov rdi, [rax+8]        ; argv[1]
    lea rsi, [rel vault_flag]
    call strcmp
    test eax, eax
    jnz .no_vault_flag

    ; --vault mode: need argc >= 4
    mov rax, [rel argc]
    cmp rax, 4
    jl show_usage

    ; Save vault name and rebuild path
    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = vault name
    lea rdi, [rel vault_name]
    call strcpy

    ; Rebuild vault_path: HOME + /.vault-<name>/vault.enc
    call build_named_vault_path

    ; Shift argv
    mov rax, [rel argc]
    sub rax, 2
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 16
    mov [rel argv], rax
.no_vault_flag:

    ; Check for --vault-path flag: vault --vault-path /path/to/vault.enc <command> [args]
    mov rax, [rel argv]
    mov rdi, [rax+8]        ; argv[1]
    lea rsi, [rel vault_path_flag]
    call strcmp
    test eax, eax
    jnz .no_vault_path_flag

    ; --vault-path mode: need argc >= 4
    mov rax, [rel argc]
    cmp rax, 4
    jl show_usage

    ; Override vault_path directly
    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = vault path
    lea rdi, [rel vault_path]
    call strcpy

    ; Shift argv
    mov rax, [rel argc]
    sub rax, 2
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 16
    mov [rel argv], rax
.no_vault_path_flag:

    ; --v4 flag (must come after --vault-path/--keyfile so it sees the
    ; right argv[1] regardless of which flags preceded the command).
    mov byte [rel v4_flag], 0
    mov rax, [rel argv]
    mov rdi, [rax+8]
    lea rsi, [rel v4_flag_str]
    call strcmp
    test eax, eax
    jnz .no_v4_flag2
    mov byte [rel v4_flag], 1
    mov rax, [rel argc]
    dec rax
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 8
    mov [rel argv], rax
.no_v4_flag2:

    ; Load config file (sets config_gen_len)
    call load_config

    ; Get argv[1] (command)
    mov rax, [rel argv]
    mov rdi, [rax+8]        ; argv[1]

    ; ── Dispatch commands ────────────────────────────────────
    lea rsi, [rel cmd_test_sha]
    call strcmp
    test eax, eax
    jz cmd_test_sha256

    mov rax, [rel argv]
    mov rdi, [rax+8]
    lea rsi, [rel cmd_test_cc]
    call strcmp
    test eax, eax
    jz cmd_test_chacha20

    lea rsi, [rel cmd_init]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_init

    lea rsi, [rel cmd_add]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_add

    lea rsi, [rel cmd_get]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_get

    lea rsi, [rel cmd_list]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_list

    lea rsi, [rel cmd_gen]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_gen

    lea rsi, [rel cmd_rm]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_rm

    lea rsi, [rel cmd_export]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_export

    lea rsi, [rel cmd_import]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_import

    lea rsi, [rel cmd_show]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_show

    lea rsi, [rel cmd_search]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_search

    lea rsi, [rel cmd_count]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_count

    lea rsi, [rel cmd_edit]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_edit

    lea rsi, [rel cmd_clip]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_clip

    lea rsi, [rel cmd_totp]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_totp

    lea rsi, [rel cmd_verify]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_verify

    lea rsi, [rel cmd_backup]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_backup

    lea rsi, [rel cmd_wipe]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_wipe

    lea rsi, [rel cmd_unlock]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_unlock

    lea rsi, [rel cmd_lock]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_lock

    lea rsi, [rel cmd_hidden]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_hidden

    lea rsi, [rel cmd_migrate]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_migrate

    lea rsi, [rel cmd_help]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_help

    lea rsi, [rel cmd_status]
    mov rdi, [rel argv]
    mov rdi, [rdi+8]
    call strcmp
    test eax, eax
    jz do_status

    ; Fall-through: argv[1] is not a recognized command.
    ; Distinct from the no-args case (which jumps to show_usage directly).
err_unknown_command:
    lea rdi, [rel err_msg_unknown_cmd]
    lea rsi, [rel err_code_unknown_cmd]
    lea rdx, [rel msg_unknown_cmd]
    mov ecx, 2
    call emit_err

show_usage:
    lea rdi, [rel msg_usage]
    call print_str
    xor edi, edi
    call exit

do_help:
    mov rax, [rel argv]
    mov rdi, [rax+16]       ; argv[2] = help topic
    test rdi, rdi
    jz show_usage

    lea rsi, [rel cmd_init]
    call strcmp
    test eax, eax
    jnz .help_add
    lea rdi, [rel msg_help_init]
    call print_str
    xor edi, edi
    call exit

.help_add:
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel cmd_add]
    call strcmp
    test eax, eax
    jnz .help_get
    lea rdi, [rel msg_help_add]
    call print_str
    xor edi, edi
    call exit

.help_get:
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel cmd_get]
    call strcmp
    test eax, eax
    jnz .help_backup
    lea rdi, [rel msg_help_get]
    call print_str
    xor edi, edi
    call exit

.help_backup:
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel cmd_backup]
    call strcmp
    test eax, eax
    jnz .help_verify
    lea rdi, [rel msg_help_backup]
    call print_str
    xor edi, edi
    call exit

.help_verify:
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel cmd_verify]
    call strcmp
    test eax, eax
    jnz .help_unknown
    lea rdi, [rel msg_help_verify]
    call print_str
    xor edi, edi
    call exit

.help_unknown:
    lea rdi, [rel msg_help_unknown]
    call print_str
    xor edi, edi
    call exit

; ════════════════════════════════════════════════════════════════
; build_vault_path — construct ~/.vault/vault.enc path
; ════════════════════════════════════════════════════════════════
build_vault_path:
    push rbx
    push rcx
    push rdx
    ; Walk environment to find HOME=
    mov rax, [rel argc]
    mov rbx, [rel argv]
    lea rbx, [rbx + rax*8 + 8]   ; envp = argv + argc + 1 (null)
.env_loop:
    mov rdi, [rbx]
    test rdi, rdi
    jz .env_done
    ; Check if starts with "HOME="
    cmp byte [rdi], 'H'
    jne .env_next
    cmp byte [rdi+1], 'O'
    jne .env_next
    cmp byte [rdi+2], 'M'
    jne .env_next
    cmp byte [rdi+3], 'E'
    jne .env_next
    cmp byte [rdi+4], '='
    jne .env_next
    ; Found HOME=, copy value
    lea rsi, [rdi+5]
    lea rdi, [rel vault_path]
    call strcpy
    ; Append /.vault/vault.enc
    lea rdi, [rel vault_path]
    call strlen
    lea rdi, [rel vault_path]
    add rdi, rax
    lea rsi, [rel vault_file_tpl]
    call strcpy
    jmp .env_done
.env_next:
    add rbx, 8
    jmp .env_loop
.env_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; try_env_pass — check VAULT_PASS environment variable
;   If found, copies value to master_pw buffer
;   Returns: eax = 1 if found, 0 if not
; ════════════════════════════════════════════════════════════════
try_env_pass:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rax, [rel argc]
    mov rbx, [rel argv]
    lea rbx, [rbx + rax*8 + 8]   ; envp = argv + argc + 1
.tep_loop:
    mov rdi, [rbx]
    test rdi, rdi
    jz .tep_notfound
    ; Check "VAULT_PASS="
    cmp byte [rdi],   'V'
    jne .tep_next
    cmp byte [rdi+1], 'A'
    jne .tep_next
    cmp byte [rdi+2], 'U'
    jne .tep_next
    cmp byte [rdi+3], 'L'
    jne .tep_next
    cmp byte [rdi+4], 'T'
    jne .tep_next
    cmp byte [rdi+5], '_'
    jne .tep_next
    cmp byte [rdi+6], 'P'
    jne .tep_next
    cmp byte [rdi+7], 'A'
    jne .tep_next
    cmp byte [rdi+8], 'S'
    jne .tep_next
    cmp byte [rdi+9], 'S'
    jne .tep_next
    cmp byte [rdi+10], '='
    jne .tep_next
    ; Found — copy value after '=' to master_pw, then SCRUB the env value
    ; in-place so /proc/<pid>/environ no longer reveals the password.
    ; envp memory is writable (kernel sets up envp on the initial stack).
    lea rsi, [rdi+11]
    lea rdi, [rel master_pw]
    xor ecx, ecx
.tep_copy:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz .tep_scrub
    inc ecx
    cmp ecx, 255
    jl .tep_copy
    mov byte [rdi + 255], 0
.tep_scrub:
    ; Overwrite VAULT_PASS=… value bytes in envp memory.
    ; rsi still points at the env value start. Walk and zero until null,
    ; bounded by 4096 to avoid runaway in a corrupted environment block.
    xor ecx, ecx
.tep_scrub_loop:
    mov al, [rsi + rcx]
    test al, al
    jz .tep_scrub_done
    mov byte [rsi + rcx], 0
    inc ecx
    cmp ecx, 4096
    jl .tep_scrub_loop
.tep_scrub_done:
.tep_found:
    mov eax, 1
    jmp .tep_ret
.tep_next:
    add rbx, 8
    jmp .tep_loop
.tep_notfound:
    xor eax, eax
.tep_ret:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; SHA-256 Implementation
; ════════════════════════════════════════════════════════════════

; sha256_init — initialize state with H values
sha256_init:
    push rsi
    push rdi
    push rcx
    lea rsi, [rel sha256_h_init]
    lea rdi, [rel sha256_state]
    mov ecx, 8
.copy:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .copy
    mov qword [rel sha256_bitlen], 0
    mov dword [rel sha256_buflen], 0
    pop rcx
    pop rdi
    pop rsi
    ret

; sha256_update — feed data into SHA-256
;   rdi = data pointer
;   rsi = data length
sha256_update:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    mov r12, rdi            ; data ptr
    mov r13, rsi            ; data len

.update_loop:
    test r13, r13
    jz .update_done

    ; How much space in block buffer?
    mov eax, [rel sha256_buflen]
    mov ecx, 64
    sub ecx, eax            ; space left

    ; How much to copy?
    mov rdx, r13
    cmp rdx, rcx
    jbe .copy_amt_ok
    mov rdx, rcx
.copy_amt_ok:
    ; Copy rdx bytes from r12 to sha256_block + buflen
    lea rdi, [rel sha256_block]
    mov eax, [rel sha256_buflen]
    add rdi, rax
    mov rsi, r12
    mov rcx, rdx
    rep movsb

    add r12, rdx
    sub r13, rdx
    mov eax, [rel sha256_buflen]
    add eax, edx
    mov [rel sha256_buflen], eax

    ; If block is full, process it
    cmp eax, 64
    jne .update_loop
    call sha256_transform
    mov dword [rel sha256_buflen], 0
    ; Add 512 bits to bitlen
    mov rax, [rel sha256_bitlen]
    add rax, 512
    mov [rel sha256_bitlen], rax
    jmp .update_loop

.update_done:
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; sha256_final — finalize and output digest
;   rdi = output buffer (32 bytes)
sha256_final:
    push rbx
    push rcx
    push rdx
    push r12
    mov r12, rdi            ; output ptr

    ; Add remaining bits to bitlen
    mov eax, [rel sha256_buflen]
    mov eax, eax             ; zero-extend eax into rax
    shl rax, 3              ; bytes to bits
    add [rel sha256_bitlen], rax

    ; Pad: append 0x80
    mov eax, [rel sha256_buflen]
    lea rdi, [rel sha256_block]
    mov byte [rdi + rax], 0x80
    inc eax

    ; If buflen > 56, pad to 64, transform, then pad new block
    cmp eax, 56
    jle .pad_zeros
    ; Zero rest of block
    lea rdi, [rel sha256_block]
    add rdi, rax
    mov ecx, 64
    sub ecx, eax
    xor al, al
    rep stosb
    call sha256_transform
    ; Start fresh block of zeros
    lea rdi, [rel sha256_block]
    mov ecx, 56
    xor al, al
    rep stosb
    jmp .append_len

.pad_zeros:
    lea rdi, [rel sha256_block]
    add rdi, rax
    mov ecx, 56
    sub ecx, eax
    xor al, al
    rep stosb

.append_len:
    ; Append 64-bit big-endian bit length at bytes 56..63
    mov rax, [rel sha256_bitlen]
    lea rdi, [rel sha256_block]
    bswap rax
    mov [rdi + 56], rax
    call sha256_transform

    ; Output state as big-endian bytes
    lea rsi, [rel sha256_state]
    mov rdi, r12
    mov ecx, 8
.output:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .output

    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; sha256_transform — process one 64-byte block
;   Uses sha256_block as input
sha256_transform:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; ── Prepare message schedule W[0..63] ────────────────────
    lea rsi, [rel sha256_block]
    lea rdi, [rel sha256_w]

    ; W[0..15] = big-endian 32-bit words from block
    mov ecx, 16
.load_w:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .load_w

    ; W[16..63]: W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
    lea rdi, [rel sha256_w]
    mov ecx, 16
.expand_w:
    cmp ecx, 64
    jge .expand_done

    ; σ1(W[i-2]): ROTR17 ^ ROTR19 ^ SHR10
    mov eax, [rdi + rcx*4 - 8]     ; W[i-2]
    mov ebx, eax
    ror eax, 17
    mov edx, ebx
    ror edx, 19
    xor eax, edx
    mov edx, ebx
    shr edx, 10
    xor eax, edx
    mov r8d, eax            ; σ1

    ; W[i-7]
    add r8d, [rdi + rcx*4 - 28]

    ; σ0(W[i-15]): ROTR7 ^ ROTR18 ^ SHR3
    mov eax, [rdi + rcx*4 - 60]    ; W[i-15]
    mov ebx, eax
    ror eax, 7
    mov edx, ebx
    ror edx, 18
    xor eax, edx
    mov edx, ebx
    shr edx, 3
    xor eax, edx
    add r8d, eax            ; + σ0

    ; + W[i-16]
    add r8d, [rdi + rcx*4 - 64]

    mov [rdi + rcx*4], r8d
    inc ecx
    jmp .expand_w
.expand_done:

    ; ── Initialize working variables from state ──────────────
    lea rsi, [rel sha256_state]
    mov r8d, [rsi]          ; a
    mov r9d, [rsi+4]        ; b
    mov r10d, [rsi+8]       ; c
    mov r11d, [rsi+12]      ; d
    mov r12d, [rsi+16]      ; e
    mov r13d, [rsi+20]      ; f
    mov r14d, [rsi+24]      ; g
    mov r15d, [rsi+28]      ; h

    ; ── 64 rounds ────────────────────────────────────────────
    lea rsi, [rel sha256_k]
    lea rdi, [rel sha256_w]
    xor ecx, ecx
.round:
    cmp ecx, 64
    jge .round_done

    ; Σ1(e) = ROTR6(e) ^ ROTR11(e) ^ ROTR25(e)
    mov eax, r12d
    ror eax, 6
    mov ebx, r12d
    ror ebx, 11
    xor eax, ebx
    mov ebx, r12d
    ror ebx, 25
    xor eax, ebx           ; Σ1

    ; Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
    mov edx, r12d
    and edx, r13d
    mov ebp, r12d
    not ebp
    and ebp, r14d
    xor edx, ebp           ; Ch

    ; T1 = h + Σ1 + Ch + K[i] + W[i]
    mov ebp, r15d           ; h
    add ebp, eax            ; + Σ1
    add ebp, edx            ; + Ch
    add ebp, [rsi + rcx*4]  ; + K[i]
    add ebp, [rdi + rcx*4]  ; + W[i]

    ; Σ0(a) = ROTR2(a) ^ ROTR13(a) ^ ROTR22(a)
    mov eax, r8d
    ror eax, 2
    mov ebx, r8d
    ror ebx, 13
    xor eax, ebx
    mov ebx, r8d
    ror ebx, 22
    xor eax, ebx           ; Σ0

    ; Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    mov edx, r8d
    and edx, r9d
    mov ebx, r8d
    and ebx, r10d
    xor edx, ebx
    mov ebx, r9d
    and ebx, r10d
    xor edx, ebx           ; Maj

    ; T2 = Σ0 + Maj
    add eax, edx           ; T2

    ; Rotate: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
    mov r15d, r14d          ; h = g
    mov r14d, r13d          ; g = f
    mov r13d, r12d          ; f = e
    mov r12d, r11d
    add r12d, ebp           ; e = d + T1
    mov r11d, r10d          ; d = c
    mov r10d, r9d           ; c = b
    mov r9d, r8d            ; b = a
    mov r8d, ebp
    add r8d, eax            ; a = T1 + T2

    inc ecx
    jmp .round

.round_done:
    ; Add working variables to state
    lea rsi, [rel sha256_state]
    add [rsi], r8d
    add [rsi+4], r9d
    add [rsi+8], r10d
    add [rsi+12], r11d
    add [rsi+16], r12d
    add [rsi+20], r13d
    add [rsi+24], r14d
    add [rsi+28], r15d

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; sha256_hash — convenience: hash a buffer, output digest
;   rdi = input data
;   rsi = input length
;   rdx = output buffer (32 bytes)
sha256_hash:
    push r12
    mov r12, rdx
    push rdi
    push rsi
    call sha256_init
    pop rsi
    pop rdi
    call sha256_update
    mov rdi, r12
    call sha256_final
    pop r12
    ret

; ════════════════════════════════════════════════════════════════
; SHA-1 Implementation
; ════════════════════════════════════════════════════════════════

sha1_init:
    push rsi
    push rdi
    push rcx
    lea rsi, [rel sha1_h_init]
    lea rdi, [rel sha1_state]
    mov ecx, 5
.copy:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .copy
    mov qword [rel sha1_bitlen], 0
    mov dword [rel sha1_buflen], 0
    pop rcx
    pop rdi
    pop rsi
    ret

sha1_update:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi

.s1_update_loop:
    test r13, r13
    jz .s1_update_done

    mov eax, [rel sha1_buflen]
    mov ecx, 64
    sub ecx, eax

    mov rdx, r13
    cmp rdx, rcx
    jbe .s1_copy_ok
    mov rdx, rcx
.s1_copy_ok:
    lea rdi, [rel sha1_block]
    mov eax, [rel sha1_buflen]
    add rdi, rax
    mov rsi, r12
    mov rcx, rdx
    rep movsb

    add r12, rdx
    sub r13, rdx
    mov eax, [rel sha1_buflen]
    add eax, edx
    mov [rel sha1_buflen], eax

    cmp eax, 64
    jne .s1_update_loop
    call sha1_transform
    mov dword [rel sha1_buflen], 0
    mov rax, [rel sha1_bitlen]
    add rax, 512
    mov [rel sha1_bitlen], rax
    jmp .s1_update_loop

.s1_update_done:
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

sha1_final:
    push rbx
    push rcx
    push rdx
    push r12
    mov r12, rdi

    mov eax, [rel sha1_buflen]
    mov eax, eax
    shl rax, 3
    add [rel sha1_bitlen], rax

    mov eax, [rel sha1_buflen]
    lea rdi, [rel sha1_block]
    mov byte [rdi + rax], 0x80
    inc eax

    cmp eax, 56
    jle .s1_pad_zeros
    lea rdi, [rel sha1_block]
    add rdi, rax
    mov ecx, 64
    sub ecx, eax
    xor al, al
    rep stosb
    call sha1_transform
    lea rdi, [rel sha1_block]
    mov ecx, 56
    xor al, al
    rep stosb
    jmp .s1_append_len

.s1_pad_zeros:
    lea rdi, [rel sha1_block]
    add rdi, rax
    mov ecx, 56
    sub ecx, eax
    xor al, al
    rep stosb

.s1_append_len:
    mov rax, [rel sha1_bitlen]
    lea rdi, [rel sha1_block]
    bswap rax
    mov [rdi + 56], rax
    call sha1_transform

    ; Output state as big-endian (20 bytes = 5 words)
    lea rsi, [rel sha1_state]
    mov rdi, r12
    mov ecx, 5
.s1_output:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .s1_output

    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; sha1_transform — process one 64-byte block
sha1_transform:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13

    ; Load block as big-endian words into W[0..15]
    lea rsi, [rel sha1_block]
    lea rdi, [rel sha1_w]
    mov ecx, 16
.s1_load_w:
    mov eax, [rsi]
    bswap eax
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .s1_load_w

    ; Expand W[16..79]: W[i] = ROTL1(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16])
    lea rdi, [rel sha1_w]
    mov ecx, 16
.s1_expand:
    cmp ecx, 80
    jge .s1_expand_done
    mov eax, [rdi + rcx*4 - 12]     ; W[i-3]
    xor eax, [rdi + rcx*4 - 32]     ; W[i-8]
    xor eax, [rdi + rcx*4 - 56]     ; W[i-14]
    xor eax, [rdi + rcx*4 - 64]     ; W[i-16]
    rol eax, 1
    mov [rdi + rcx*4], eax
    inc ecx
    jmp .s1_expand
.s1_expand_done:

    ; Working variables
    lea rsi, [rel sha1_state]
    mov r8d, [rsi]          ; a
    mov r9d, [rsi+4]        ; b
    mov r10d, [rsi+8]       ; c
    mov r11d, [rsi+12]      ; d
    mov r12d, [rsi+16]      ; e

    lea rdi, [rel sha1_w]
    lea rsi, [rel sha1_k]
    xor ecx, ecx

.s1_round:
    cmp ecx, 80
    jge .s1_round_done

    ; T = ROTL5(a) + f(b,c,d) + e + K[t] + W[t]
    mov eax, r8d
    rol eax, 5              ; ROTL5(a)
    add eax, r12d           ; + e
    add eax, [rdi + rcx*4]  ; + W[t]

    ; Select K and f based on round
    cmp ecx, 20
    jl .s1_f0
    cmp ecx, 40
    jl .s1_f1
    cmp ecx, 60
    jl .s1_f2
    ; rounds 60-79: f = b XOR c XOR d, K[3]
    mov edx, r9d
    xor edx, r10d
    xor edx, r11d
    add eax, [rsi + 12]
    jmp .s1_apply
.s1_f0:
    ; rounds 0-19: f = (b AND c) OR (NOT b AND d), K[0]
    mov edx, r9d
    and edx, r10d
    mov ebp, r9d
    not ebp
    and ebp, r11d
    or edx, ebp
    add eax, [rsi]
    jmp .s1_apply
.s1_f1:
    ; rounds 20-39: f = b XOR c XOR d, K[1]
    mov edx, r9d
    xor edx, r10d
    xor edx, r11d
    add eax, [rsi + 4]
    jmp .s1_apply
.s1_f2:
    ; rounds 40-59: f = (b AND c) OR (b AND d) OR (c AND d), K[2]
    mov edx, r9d
    and edx, r10d
    mov ebp, r9d
    and ebp, r11d
    or edx, ebp
    mov ebp, r10d
    and ebp, r11d
    or edx, ebp
    add eax, [rsi + 8]

.s1_apply:
    add eax, edx           ; T = ROTL5(a) + f + e + K + W

    ; Rotate: e=d, d=c, c=ROTL30(b), b=a, a=T
    mov r12d, r11d          ; e = d
    mov r11d, r10d          ; d = c
    mov r10d, r9d
    rol r10d, 30            ; c = ROTL30(b)
    mov r9d, r8d            ; b = a
    mov r8d, eax            ; a = T

    inc ecx
    jmp .s1_round

.s1_round_done:
    lea rsi, [rel sha1_state]
    add [rsi], r8d
    add [rsi+4], r9d
    add [rsi+8], r10d
    add [rsi+12], r11d
    add [rsi+16], r12d

    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; sha1_hash — convenience: hash buffer, output 20-byte digest
;   rdi = input, rsi = length, rdx = output (20 bytes)
sha1_hash:
    push r12
    mov r12, rdx
    push rdi
    push rsi
    call sha1_init
    pop rsi
    pop rdi
    call sha1_update
    mov rdi, r12
    call sha1_final
    pop r12
    ret

; ════════════════════════════════════════════════════════════════
; Blake2b Implementation
; ════════════════════════════════════════════════════════════════

; blake2b_init — initialize Blake2b state
;   edi = output length (1-64)
blake2b_init:
    push rcx
    push rsi
    push rdi
    mov [rel b2b_outlen], edi

    ; Copy IV to state
    lea rsi, [rel blake2b_iv]
    lea rdi, [rel b2b_h]
    mov ecx, 8
.b2i_copy:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .b2i_copy

    ; XOR h[0] with parameter block: outlen | (keylen=0)<<8 | fanout=1<<16 | depth=1<<24
    pop rdi                 ; outlen
    push rdi
    mov eax, edi             ; zero-extends to rax
    or rax, 0x01010000       ; fanout=1, depth=1, no key
    lea rdi, [rel b2b_h]
    xor [rdi], rax

    mov dword [rel b2b_buflen], 0
    mov qword [rel b2b_counter], 0
    mov qword [rel b2b_counter + 8], 0

    pop rdi
    pop rsi
    pop rcx
    ret

; blake2b_update — feed data to Blake2b
;   rdi = data, rsi = length
blake2b_update:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi

.b2u_loop:
    test r13, r13
    jz .b2u_done

    ; If buffer is full (128 bytes), compress it
    mov eax, [rel b2b_buflen]
    cmp eax, 128
    jne .b2u_fill

    ; Increment counter by 128
    add qword [rel b2b_counter], 128
    adc qword [rel b2b_counter + 8], 0

    ; Compress (not final)
    xor edi, edi            ; not_last = 0 means not final
    call blake2b_compress
    mov dword [rel b2b_buflen], 0

.b2u_fill:
    mov eax, [rel b2b_buflen]
    mov ecx, 128
    sub ecx, eax            ; space left
    mov rdx, r13
    cmp rdx, rcx
    jbe .b2u_copy_ok
    mov rdx, rcx
.b2u_copy_ok:
    lea rdi, [rel b2b_buf]
    add rdi, rax
    mov rsi, r12
    mov rcx, rdx
    rep movsb

    add r12, rdx
    sub r13, rdx
    mov eax, [rel b2b_buflen]
    add eax, edx
    mov [rel b2b_buflen], eax
    jmp .b2u_loop

.b2u_done:
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; blake2b_final — finalize and output hash
;   rdi = output buffer, esi = output length
blake2b_final:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi

    ; Increment counter by remaining bytes
    mov eax, [rel b2b_buflen]
    ; eax already zero-extends to rax
    add [rel b2b_counter], rax
    adc qword [rel b2b_counter + 8], 0

    ; Zero-pad remaining buffer
    mov eax, [rel b2b_buflen]
    lea rdi, [rel b2b_buf]
    add rdi, rax
    mov ecx, 128
    sub ecx, eax
    xor al, al
    rep stosb

    ; Compress with final flag
    mov edi, 1              ; is_last = 1
    call blake2b_compress

    ; Copy output (little-endian state words)
    lea rsi, [rel b2b_h]
    mov rdi, r12
    mov ecx, r13d
    rep movsb

    pop r13
    pop r12
    pop rbx
    ret

; blake2b_compress — core compression function
;   edi = is_last (1 if final block, 0 otherwise)
blake2b_compress:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8              ; align stack
    mov [rsp], edi          ; save is_last

    ; Initialize working vector v[0..15]
    ; v[0..7] = h[0..7]
    lea rsi, [rel b2b_h]
    lea rdi, [rel b2b_v]
    mov ecx, 8
.b2c_copy_h:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .b2c_copy_h

    ; v[8..11] = IV[0..3]
    lea rsi, [rel blake2b_iv]
    mov ecx, 4
.b2c_copy_iv1:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .b2c_copy_iv1

    ; v[12] = IV[4] XOR counter_lo
    mov rax, [rsi]
    xor rax, [rel b2b_counter]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8

    ; v[13] = IV[5] XOR counter_hi
    mov rax, [rsi]
    xor rax, [rel b2b_counter + 8]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8

    ; v[14] = IV[6] XOR (is_last ? 0xFFFFFFFFFFFFFFFF : 0)
    mov rax, [rsi]
    mov ecx, [rsp]          ; is_last
    test ecx, ecx
    jz .b2c_no_final
    mov rcx, -1             ; 0xFFFFFFFFFFFFFFFF
    xor rax, rcx
.b2c_no_final:
    mov [rdi], rax
    add rsi, 8
    add rdi, 8

    ; v[15] = IV[7]
    mov rax, [rsi]
    mov [rdi], rax

    ; Load message words (little-endian, 16 x 64-bit)
    lea rsi, [rel b2b_buf]
    lea rdi, [rel b2b_m]
    mov ecx, 16
.b2c_load_m:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .b2c_load_m

    ; 12 rounds
    lea r14, [rel blake2b_sigma]
    xor r15d, r15d          ; round counter

.b2c_round:
    cmp r15d, 12
    jge .b2c_rounds_done

    ; Get sigma for this round: 16 byte indices
    mov rbx, r15
    shl rbx, 4              ; r15 * 16
    add rbx, r14             ; + sigma base

    ; G(v, 0, 4,  8, 12, m[sigma[0]], m[sigma[1]])
    ; G(v, 1, 5,  9, 13, m[sigma[2]], m[sigma[3]])
    ; G(v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]])
    ; G(v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]])
    ; G(v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]])
    ; G(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]])
    ; G(v, 2, 7,  8, 13, m[sigma[12]], m[sigma[13]])
    ; G(v, 3, 4,  9, 14, m[sigma[14]], m[sigma[15]])

    lea rdi, [rel b2b_v]
    lea rsi, [rel b2b_m]

    ; Column round: 4 G calls
    %macro B2B_G 6  ; a_idx, b_idx, c_idx, d_idx, mx_off, my_off
        movzx eax, byte [rbx + %5]
        mov r8, [rsi + rax*8]       ; mx
        movzx eax, byte [rbx + %6]
        mov r9, [rsi + rax*8]       ; my

        mov rax, [rdi + %1*8]       ; a
        add rax, [rdi + %2*8]       ; a += b
        add rax, r8                 ; a += mx
        mov [rdi + %1*8], rax

        mov rcx, [rdi + %4*8]       ; d
        xor rcx, rax                ; d ^= a
        ror rcx, 32                 ; d >>>= 32
        mov [rdi + %4*8], rcx

        mov rax, [rdi + %3*8]       ; c
        add rax, rcx                ; c += d
        mov [rdi + %3*8], rax

        mov rcx, [rdi + %2*8]       ; b
        xor rcx, rax                ; b ^= c
        ror rcx, 24                 ; b >>>= 24
        mov [rdi + %2*8], rcx

        mov rax, [rdi + %1*8]       ; a
        add rax, rcx                ; a += b
        add rax, r9                 ; a += my
        mov [rdi + %1*8], rax

        mov rcx, [rdi + %4*8]       ; d
        xor rcx, rax                ; d ^= a
        ror rcx, 16                 ; d >>>= 16
        mov [rdi + %4*8], rcx

        mov rax, [rdi + %3*8]       ; c
        add rax, rcx                ; c += d
        mov [rdi + %3*8], rax

        mov rcx, [rdi + %2*8]       ; b
        xor rcx, rax                ; b ^= c
        ror rcx, 63                 ; b >>>= 63
        mov [rdi + %2*8], rcx
    %endmacro

    ; Columns
    B2B_G  0, 4,  8, 12,  0,  1
    B2B_G  1, 5,  9, 13,  2,  3
    B2B_G  2, 6, 10, 14,  4,  5
    B2B_G  3, 7, 11, 15,  6,  7
    ; Diagonals
    B2B_G  0, 5, 10, 15,  8,  9
    B2B_G  1, 6, 11, 12, 10, 11
    B2B_G  2, 7,  8, 13, 12, 13
    B2B_G  3, 4,  9, 14, 14, 15

    inc r15d
    jmp .b2c_round

.b2c_rounds_done:
    ; h[i] ^= v[i] ^ v[i+8]
    lea rdi, [rel b2b_h]
    lea rsi, [rel b2b_v]
    mov ecx, 8
.b2c_finalize:
    mov rax, [rdi]
    xor rax, [rsi]
    xor rax, [rsi + 64]
    mov [rdi], rax
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .b2c_finalize

    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; blake2b_hash — convenience: hash buffer to output
;   rdi = input, rsi = input_len, rdx = output, ecx = output_len
blake2b_hash:
    push r12
    push r13
    mov r12, rdx            ; output
    mov r13d, ecx           ; outlen
    push rdi
    push rsi
    mov edi, r13d
    call blake2b_init
    pop rsi
    pop rdi
    call blake2b_update
    mov rdi, r12
    mov esi, r13d
    call blake2b_final
    pop r13
    pop r12
    ret

; ════════════════════════════════════════════════════════════════
; Argon2id Implementation
; ════════════════════════════════════════════════════════════════

; argon2id_hash — derive key using Argon2id
;   rdi = password, rsi = pw_len
;   rdx = salt, rcx = salt_len
;   r8  = output (32 bytes)
argon2id_hash:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8

    mov r12, rdi            ; password
    mov r13, rsi            ; pw_len
    mov r14, rdx            ; salt
    mov r15, rcx            ; salt_len
    mov rbp, r8             ; output

    ; Step 1: Compute H0 = Blake2b-512(params || password || salt)
    ; H0 is a 64-byte hash
    ; params = p(4) || taglen(4) || m(4) || t(4) || v(4) || type(4) || pwlen(4) || pw || saltlen(4) || salt
    ; We'll build the input block and hash it

    ; Use argon2_h0 area as temp for building input
    ; Actually, we feed Blake2b incrementally
    mov edi, 64             ; 64-byte output
    call blake2b_init

    ; Feed: parallelism (4 bytes LE)
    sub rsp, 4
    mov dword [rsp], ARGON2_LANES
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: tag length
    sub rsp, 4
    mov dword [rsp], ARGON2_TAGLEN
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: memory size
    sub rsp, 4
    mov dword [rsp], ARGON2_MEMORY
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: iterations
    sub rsp, 4
    mov dword [rsp], ARGON2_ITER
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: version
    sub rsp, 4
    mov dword [rsp], ARGON2_VERSION
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: type (2 = Argon2id)
    sub rsp, 4
    mov dword [rsp], ARGON2_TYPE_ID
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4

    ; Feed: password length + password
    sub rsp, 4
    mov eax, r13d
    mov [rsp], eax
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4
    mov rdi, r12
    mov rsi, r13
    call blake2b_update

    ; Feed: salt length + salt
    sub rsp, 4
    mov eax, r15d
    mov [rsp], eax
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4
    mov rdi, r14
    mov rsi, r15
    call blake2b_update

    ; Feed: secret length (0) + associated data length (0)
    sub rsp, 8
    mov dword [rsp], 0      ; secret len
    mov dword [rsp+4], 0    ; ad len
    mov rdi, rsp
    mov rsi, 8
    call blake2b_update
    add rsp, 8

    ; Finalize H0
    lea rdi, [rel argon2_h0]
    mov esi, 64
    call blake2b_final

    ; Step 2: Allocate memory arena (16 MiB)
    xor edi, edi            ; addr = NULL
    mov rsi, ARGON2_MEMORY * ARGON2_BLOCK  ; 16 MiB
    mov edx, PROT_READ | PROT_WRITE
    mov r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov r8d, -1             ; fd = -1
    xor r9d, r9d            ; offset = 0
    mov eax, SYS_MMAP
    syscall
    test rax, rax
    js .argon2_mmap_fail
    mov [rel argon2_arena], rax

    ; Step 3: Initialize first two blocks B[0] and B[1]
    ; B[0] = H'(H0 || 0_32bit || 0_32bit)  (block index 0, lane 0)
    ; B[1] = H'(H0 || 0_32bit || 1_32bit)  (block index 1, lane 0)
    ; H' is variable-length Blake2b hash (produces 1024 bytes)

    ; Generate B[0]: H'(H0 || LE32(0) || LE32(0))
    ; First build the 72-byte input: H0(64) + lane(4) + block_idx(4)
    sub rsp, 72
    lea rdi, [rsp]
    lea rsi, [rel argon2_h0]
    mov ecx, 64
    rep movsb
    mov dword [rsp + 64], 0  ; lane = 0
    mov dword [rsp + 68], 0  ; block index = 0
    mov rdi, rsp
    mov rsi, 72
    mov rdx, [rel argon2_arena]  ; output = B[0]
    call argon2_hash_long

    ; Generate B[1]
    mov dword [rsp + 68], 1  ; block index = 1
    mov rdi, rsp
    mov rsi, 72
    mov rdx, [rel argon2_arena]
    add rdx, ARGON2_BLOCK   ; output = B[1]
    call argon2_hash_long
    add rsp, 72

    ; Step 4: Fill remaining blocks for each pass
    ; For Argon2id: first half of pass 0 uses data-independent addressing
    ;              rest uses data-dependent addressing
    xor ebx, ebx           ; pass counter
.argon2_pass:
    cmp ebx, ARGON2_ITER
    jge .argon2_extract

    ; Fill blocks 2..ARGON2_MEMORY-1
    mov r14d, 2             ; start from block 2 (0 and 1 already filled)
    cmp ebx, 0
    jne .argon2_fill_start
    ; Pass 0 starts from block 2
    jmp .argon2_fill_start

.argon2_fill_loop:
    cmp r14d, ARGON2_MEMORY
    jge .argon2_pass_done

.argon2_fill_start:
    ; Determine reference block index
    ; For Argon2id: if pass==0 and block_idx < MEMORY/2, use data-independent (pseudo-random)
    ;              else use data-dependent (from previous block's first 8 bytes)

    ; Previous block index (wraps around)
    mov eax, r14d
    test eax, eax
    jnz .argon2_prev_ok
    mov eax, ARGON2_MEMORY  ; wrap: prev of block 0 is last block
.argon2_prev_ok:
    dec eax                 ; prev = current - 1 (or MEMORY-1 if current==0)

    ; Get first 8 bytes of previous block as J1
    mov rcx, [rel argon2_arena]
    imul rax, ARGON2_BLOCK
    mov r8, [rcx + rax]     ; J1 = first 8 bytes of B[prev]

    ; Reference index: J1 mod (current_index)
    ; But ensure we don't reference the current block
    xor edx, edx
    mov rax, r8
    ; Reference range: on pass 0, use 0..current-1; on later passes, use full range
    cmp ebx, 0              ; pass counter
    jne .argon2_ref_full
    mov rcx, r14            ; current index
    test rcx, rcx
    jz .argon2_ref_zero
    div rcx
    jmp .argon2_do_fill
.argon2_ref_full:
    mov rcx, ARGON2_MEMORY
    div rcx
    jmp .argon2_do_fill
.argon2_ref_zero:
    xor edx, edx

.argon2_do_fill:
    ; G(B[current], B[prev], B[ref])
    ; B[current] = G(B[current-1], B[ref])
    ; new_block = compress(prev_block, ref_block)
    mov rax, [rel argon2_arena]

    ; src1 = B[prev] (with wrap-around)
    mov ecx, r14d
    test ecx, ecx
    jnz .argon2_prev_ok2
    mov ecx, ARGON2_MEMORY
.argon2_prev_ok2:
    dec ecx
    imul rcx, ARGON2_BLOCK
    lea rdi, [rax + rcx]    ; prev block

    ; src2 = B[ref]
    mov ecx, edx             ; zero-extends
    imul rcx, ARGON2_BLOCK
    lea rsi, [rax + rcx]    ; ref block

    ; dst = B[current]
    mov ecx, r14d
    imul rcx, ARGON2_BLOCK
    lea rdx, [rax + rcx]    ; current block

    call argon2_compress_blocks

    inc r14d
    jmp .argon2_fill_loop

.argon2_pass_done:
    inc ebx
    ; For subsequent passes, start from block 0
    mov r14d, 0
    cmp ebx, ARGON2_ITER
    jl .argon2_fill_start
    jmp .argon2_extract

.argon2_extract:
    ; Step 5: Extract tag from final block
    ; tag = H'(B[MEMORY-1], TAGLEN)
    mov rax, [rel argon2_arena]
    mov rcx, (ARGON2_MEMORY - 1) * ARGON2_BLOCK
    lea rdi, [rax + rcx]    ; final block
    mov rsi, ARGON2_BLOCK
    mov rdx, rbp             ; output buffer
    mov ecx, ARGON2_TAGLEN
    call blake2b_hash

    ; Step 6: Free memory arena
    mov rdi, [rel argon2_arena]
    mov rsi, ARGON2_MEMORY * ARGON2_BLOCK
    mov eax, SYS_MUNMAP
    syscall

    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.argon2_mmap_fail:
    ; Fallback: cannot allocate memory, exit with error
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; argon2_hash_long — variable-length hash H' for Argon2
;   rdi = input, rsi = input_len, rdx = output (1024 bytes)
argon2_hash_long:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi            ; input
    mov r13, rsi            ; input_len
    mov r14, rdx            ; output

    ; H'(X) for 1024 bytes:
    ; V1 = Blake2b-64(LE32(1024) || X)
    ; V2 = Blake2b-64(V1)
    ; ...repeat, taking 32 bytes from each except last which takes 64
    ; Total: ceil(1024/32) - 1 = 31 intermediate + 1 final = 32 hashes
    ; But actually: r = ceil(outlen/32) - 2, and we do r+1 Blake2b-64 hashes
    ; First 31 take first 32 bytes, last one is 64 bytes

    ; Simplified: generate 1024 bytes by hashing repeatedly
    ; First hash: Blake2b-64(LE32(1024) || input)
    mov edi, 64
    call blake2b_init
    sub rsp, 4
    mov dword [rsp], 1024   ; output length
    mov rdi, rsp
    mov rsi, 4
    call blake2b_update
    add rsp, 4
    mov rdi, r12
    mov rsi, r13
    call blake2b_update

    ; Output first hash to temp
    lea rdi, [rel argon2_tmp_block]
    mov esi, 64
    call blake2b_final

    ; Copy first 32 bytes to output
    lea rsi, [rel argon2_tmp_block]
    mov rdi, r14
    mov ecx, 32
    rep movsb

    ; Generate remaining blocks by chaining
    mov ebx, 32            ; bytes output so far
.ahl_loop:
    cmp ebx, 992           ; 1024 - 32
    jge .ahl_last

    ; Blake2b-64(previous_hash)
    mov edi, 64
    call blake2b_init
    lea rdi, [rel argon2_tmp_block]
    mov rsi, 64
    call blake2b_update
    lea rdi, [rel argon2_tmp_block]
    mov esi, 64
    call blake2b_final

    ; Copy 32 bytes to output
    lea rsi, [rel argon2_tmp_block]
    lea rdi, [r14 + rbx]
    mov ecx, 32
    rep movsb

    add ebx, 32
    jmp .ahl_loop

.ahl_last:
    ; Final block: take full 64 bytes (but we only need 32 more for 1024)
    mov edi, 64
    call blake2b_init
    lea rdi, [rel argon2_tmp_block]
    mov rsi, 64
    call blake2b_update
    lea rdi, [rel argon2_tmp_block]
    mov esi, 64
    call blake2b_final

    ; Copy remaining bytes (1024 - 992 = 32)
    lea rsi, [rel argon2_tmp_block]
    lea rdi, [r14 + rbx]
    mov ecx, 32
    rep movsb

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; argon2_compress_blocks — G function: compress two 1024-byte blocks
;   rdi = src1 (previous block), rsi = src2 (reference block), rdx = dst
;   dst = src1 XOR src2, then apply permutation P
argon2_compress_blocks:
    push rbx
    push r12
    push r13

    mov r12, rdx            ; dst

    ; R = src1 XOR src2 (1024 bytes = 128 qwords)
    lea rdx, [rel argon2_r_block]
    mov ecx, 128
.acb_xor:
    mov rax, [rdi]
    xor rax, [rsi]
    mov [rdx], rax
    mov [r12], rax          ; also store in dst initially
    add rdi, 8
    add rsi, 8
    add rdx, 8
    add r12, 8
    dec ecx
    jnz .acb_xor
    sub r12, 1024           ; reset dst pointer

    ; Apply permutation P to dst (using Blake2b G rounds on rows/columns)
    ; The block is treated as an 8x16 matrix of 8-byte words
    ; Apply P to each row of 16 words (8 calls to 2xG on pairs)
    ; Then apply P to each column

    ; For simplicity and correctness, apply the GB (Blake2b G) function
    ; to pairs of 128-byte rows, then to columns

    ; Row-wise: process 8 rows of 128 bytes each
    mov ebx, 0
.acb_row:
    cmp ebx, 8
    jge .acb_col

    ; Apply Blake2b G mixing to 16 words in this row
    ; Block is 1024 bytes = 128 qwords, arranged as 8 rows of 16 qwords
    imul eax, ebx, 128
    lea rdi, [r12 + rax]
    call argon2_permute_row

    inc ebx
    jmp .acb_row

.acb_col:
    ; Column-wise: process 8 columns
    mov ebx, 0
.acb_col_loop:
    cmp ebx, 8
    jge .acb_final

    ; Each column: words at offsets col*8, col*8+128, col*8+256, ...
    mov edi, ebx
    call argon2_permute_col

    inc ebx
    jmp .acb_col_loop

.acb_final:
    ; XOR with R: dst[i] ^= R[i]
    lea rsi, [rel argon2_r_block]
    mov rdi, r12
    mov ecx, 128
.acb_final_xor:
    mov rax, [rsi]
    xor [rdi], rax
    add rdi, 8
    add rsi, 8
    dec ecx
    jnz .acb_final_xor

    pop r13
    pop r12
    pop rbx
    ret

; argon2_permute_row — apply Blake2b G mixing to a 128-byte row (16 qwords)
;   rdi = pointer to row (16 qwords)
argon2_permute_row:
    push rbx
    ; Apply 2 rounds of G to the 16 words as pairs
    ; G(v0, v4, v8,  v12)  G(v1, v5, v9,  v13)
    ; G(v2, v6, v10, v14)  G(v3, v7, v11, v15)
    ; G(v0, v5, v10, v15)  G(v1, v6, v11, v12)
    ; G(v2, v7, v8,  v13)  G(v3, v4, v9,  v14)

    ; Column phase
    %macro ARGON2_GB 4  ; a, b, c, d (indices into row)
        mov rax, [rdi + %1*8]
        add rax, [rdi + %2*8]
        ; Add 2*lo(a)*lo(b) for the multiplication step
        mov rcx, [rdi + %1*8]
        mov rdx, [rdi + %2*8]
        mov rbx, rcx
        shl rbx, 32
        shr rbx, 32           ; lo 32 bits of a
        mov r8, rdx
        shl r8, 32
        shr r8, 32            ; lo 32 bits of b
        imul rbx, r8
        shl rbx, 1
        add rax, rbx
        mov [rdi + %1*8], rax

        mov rcx, [rdi + %4*8]
        xor rcx, rax
        ror rcx, 32
        mov [rdi + %4*8], rcx

        mov rax, [rdi + %3*8]
        add rax, rcx
        mov rbx, [rdi + %3*8]
        shl rbx, 32
        shr rbx, 32
        mov r8, rcx
        shl r8, 32
        shr r8, 32
        imul rbx, r8
        shl rbx, 1
        add rax, rbx
        mov [rdi + %3*8], rax

        mov rcx, [rdi + %2*8]
        xor rcx, rax
        ror rcx, 24
        mov [rdi + %2*8], rcx

        mov rax, [rdi + %1*8]
        add rax, rcx
        mov rbx, [rdi + %1*8]
        shl rbx, 32
        shr rbx, 32
        mov r8, rcx
        shl r8, 32
        shr r8, 32
        imul rbx, r8
        shl rbx, 1
        add rax, rbx
        mov [rdi + %1*8], rax

        mov rcx, [rdi + %4*8]
        xor rcx, rax
        ror rcx, 16
        mov [rdi + %4*8], rcx

        mov rax, [rdi + %3*8]
        add rax, rcx
        mov rbx, [rdi + %3*8]
        shl rbx, 32
        shr rbx, 32
        mov r8, rcx
        shl r8, 32
        shr r8, 32
        imul rbx, r8
        shl rbx, 1
        add rax, rbx
        mov [rdi + %3*8], rax

        mov rcx, [rdi + %2*8]
        xor rcx, rax
        ror rcx, 63
        mov [rdi + %2*8], rcx
    %endmacro

    ARGON2_GB  0,  4,  8, 12
    ARGON2_GB  1,  5,  9, 13
    ARGON2_GB  2,  6, 10, 14
    ARGON2_GB  3,  7, 11, 15
    ARGON2_GB  0,  5, 10, 15
    ARGON2_GB  1,  6, 11, 12
    ARGON2_GB  2,  7,  8, 13
    ARGON2_GB  3,  4,  9, 14

    pop rbx
    ret

; argon2_permute_col — apply permutation to column across rows
;   edi = column index (0-7)
;   Uses r12 as block pointer (set by caller argon2_compress_blocks)
argon2_permute_col:
    push rbx
    push r13
    push r14
    push r15

    ; Column permutation: for each column pair (2j, 2j+1),
    ; gather 16 qwords from 8 rows, apply P, scatter back.
    ; col index edi = pair index (0-7)

    ; Gather into argon2_tmp_block
    lea rsi, [r12]
    mov eax, edi
    shl eax, 4              ; col_pair * 16 bytes = offset within each row
    mov r15d, eax           ; SAVE column offset in r15 (callee-saved)
    lea r13, [rel argon2_tmp_block]

    mov ecx, 8              ; 8 rows
    xor ebx, ebx
.apc_gather:
    ; src = block + row*128 + col_pair*16
    imul edx, ebx, 128
    add edx, r15d
    mov r8, [rsi + rdx]
    mov [r13], r8
    mov r8, [rsi + rdx + 8]
    mov [r13 + 8], r8
    add r13, 16
    inc ebx
    dec ecx
    jnz .apc_gather

    ; Permute the 16 qwords
    lea rdi, [rel argon2_tmp_block]
    call argon2_permute_row  ; reuse the row permutation

    ; Scatter back
    lea r13, [rel argon2_tmp_block]
    ; Scatter back (using r15 for preserved column offset)
    lea r13, [rel argon2_tmp_block]
    mov eax, r15d           ; restore column offset

    mov ecx, 8
    xor ebx, ebx
.apc_scatter:
    imul edx, ebx, 128
    add edx, eax
    mov r8, [r13]
    mov [r12 + rdx], r8
    mov r8, [r13 + 8]
    mov [r12 + rdx + 8], r8
    add r13, 16
    inc ebx
    dec ecx
    jnz .apc_scatter

    pop r15
    pop r14
    pop r13
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; HMAC-SHA1
;   rdi = key, rsi = key_len, rdx = msg, rcx = msg_len, r8 = out (20 bytes)
; ════════════════════════════════════════════════════════════════
hmac_sha1:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    push r8

    ; If key > 64, hash it
    cmp r13, 64
    jbe .hs1_key_ok
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel hmac_key_buf]
    call sha1_hash
    lea r12, [rel hmac_key_buf]
    mov r13, 20
.hs1_key_ok:

    ; Zero-pad key to 64 bytes
    lea rdi, [rel hmac_key_buf]
    mov ecx, 64
    xor al, al
    rep stosb
    lea rdi, [rel hmac_key_buf]
    mov rsi, r12
    mov rcx, r13
    rep movsb

    ; ipad
    lea rsi, [rel hmac_key_buf]
    lea rdi, [rel hmac_ipad]
    mov ecx, 64
.hs1_ipad:
    mov al, [rsi]
    xor al, 0x36
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .hs1_ipad

    ; opad
    lea rsi, [rel hmac_key_buf]
    lea rdi, [rel hmac_opad]
    mov ecx, 64
.hs1_opad:
    mov al, [rsi]
    xor al, 0x5c
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .hs1_opad

    ; Inner: SHA1(ipad || msg)
    call sha1_init
    lea rdi, [rel hmac_ipad]
    mov rsi, 64
    call sha1_update
    mov rdi, r14
    mov rsi, r15
    call sha1_update
    lea rdi, [rel hmac_inner]
    call sha1_final

    ; Outer: SHA1(opad || inner)
    call sha1_init
    lea rdi, [rel hmac_opad]
    mov rsi, 64
    call sha1_update
    lea rdi, [rel hmac_inner]
    mov rsi, 20
    call sha1_update

    pop r8
    mov rdi, r8
    call sha1_final

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; HMAC-SHA256
;   rdi = key, rsi = key_len, rdx = msg, rcx = msg_len, r8 = out (32 bytes)
; ════════════════════════════════════════════════════════════════
hmac_sha256:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi            ; key
    mov r13, rsi            ; key_len
    mov r14, rdx            ; msg
    mov r15, rcx            ; msg_len
    push r8                 ; save output ptr

    ; If key > 64 bytes, hash it first
    cmp r13, 64
    jbe .key_ok
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel hmac_key_buf]
    call sha256_hash
    lea r12, [rel hmac_key_buf]
    mov r13, 32
.key_ok:

    ; Zero-pad key to 64 bytes in hmac_key_buf
    lea rdi, [rel hmac_key_buf]
    mov ecx, 64
    xor al, al
    rep stosb
    lea rdi, [rel hmac_key_buf]
    mov rsi, r12
    mov rcx, r13
    rep movsb

    ; Build ipad = key XOR 0x36 (64 bytes)
    lea rsi, [rel hmac_key_buf]
    lea rdi, [rel hmac_ipad]
    mov ecx, 64
.ipad:
    mov al, [rsi]
    xor al, 0x36
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .ipad

    ; Build opad = key XOR 0x5c (64 bytes)
    lea rsi, [rel hmac_key_buf]
    lea rdi, [rel hmac_opad]
    mov ecx, 64
.opad:
    mov al, [rsi]
    xor al, 0x5c
    mov [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .opad

    ; Inner hash: SHA256(ipad || message)
    call sha256_init
    lea rdi, [rel hmac_ipad]
    mov rsi, 64
    call sha256_update
    mov rdi, r14
    mov rsi, r15
    call sha256_update
    lea rdi, [rel hmac_inner]
    call sha256_final

    ; Outer hash: SHA256(opad || inner_hash)
    call sha256_init
    lea rdi, [rel hmac_opad]
    mov rsi, 64
    call sha256_update
    lea rdi, [rel hmac_inner]
    mov rsi, 32
    call sha256_update

    pop r8                  ; output ptr
    mov rdi, r8
    call sha256_final

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; PBKDF2-SHA256
;   rdi = password, rsi = pw_len
;   rdx = salt, rcx = salt_len
;   r8  = iterations, r9 = output (32 bytes)
; ════════════════════════════════════════════════════════════════
pbkdf2_sha256:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8              ; align stack

    mov r12, rdi            ; password
    mov r13, rsi            ; pw_len
    mov r14, rdx            ; salt
    mov r15, rcx            ; salt_len
    mov rbp, r8             ; iterations
    mov rbx, r9             ; output

    ; Build salt_i = salt || INT32BE(1) since we only need one block (32 bytes)
    lea rdi, [rel pbkdf2_salt_i]
    mov rsi, r14
    mov rcx, r15
    rep movsb
    ; Append big-endian 1
    mov dword [rdi], 0x01000000  ; INT32BE(1)
    mov rcx, r15
    add rcx, 4              ; total salt_i length

    ; U1 = HMAC-SHA256(password, salt || INT(1))
    mov rdi, r12            ; key = password
    mov rsi, r13            ; key_len
    lea rdx, [rel pbkdf2_salt_i]  ; msg = salt_i
    ; rcx already set       ; msg_len = salt_len + 4
    lea r8, [rel pbkdf2_u]
    call hmac_sha256

    ; T = U1
    lea rsi, [rel pbkdf2_u]
    lea rdi, [rel pbkdf2_t]
    mov ecx, 32
    rep movsb

    ; Iterations 2..N: U_i = HMAC(password, U_{i-1}), T ^= U_i
    mov rcx, rbp
    dec rcx                 ; already did iteration 1
.iter:
    test rcx, rcx
    jz .iter_done
    push rcx

    ; U_i = HMAC-SHA256(password, U_{i-1})
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rel pbkdf2_u]
    mov rcx, 32
    lea r8, [rel pbkdf2_u]  ; overwrite in place
    call hmac_sha256

    ; T ^= U_i
    lea rsi, [rel pbkdf2_u]
    lea rdi, [rel pbkdf2_t]
    mov ecx, 32
.xor_t:
    mov al, [rsi]
    xor [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jnz .xor_t

    pop rcx
    dec rcx
    jmp .iter

.iter_done:
    ; Copy T to output
    lea rsi, [rel pbkdf2_t]
    mov rdi, rbx
    mov ecx, 32
    rep movsb

    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; CTR mode encrypt/decrypt (SHA-256 keystream XOR) — legacy v1/v2/v3
;   rdi = key (32 bytes), rsi = iv (16 bytes)
;   rdx = input, rcx = input_len, r8 = output
; Renamed to ctr_crypt_raw; ctr_crypt is now a version-aware wrapper.
; ════════════════════════════════════════════════════════════════
ctr_crypt_raw:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi            ; key
    mov r13, rsi            ; iv
    mov r14, rdx            ; input
    mov r15, rcx            ; remaining length
    mov rbp, r8             ; output

    xor ebx, ebx           ; counter = 0

.ctr_loop:
    test r15, r15
    jz .ctr_done

    ; Build CTR input: IV(16) || counter(4) || zero-pad to 32
    lea rdi, [rel ctr_input]
    mov rsi, r13
    mov ecx, 16
    rep movsb
    ; Append counter as big-endian 32-bit
    mov eax, ebx
    bswap eax
    mov [rdi], eax
    ; Zero remaining 12 bytes
    add rdi, 4
    xor al, al
    mov ecx, 12
    rep stosb

    ; Hash: SHA256(key || ctr_input) → keystream block
    ; We'll hash key(32) + ctr_input(32) = 64 bytes
    call sha256_init
    mov rdi, r12
    mov rsi, 32
    call sha256_update
    lea rdi, [rel ctr_input]
    mov rsi, 32
    call sha256_update
    lea rdi, [rel keystream_blk]
    call sha256_final

    ; XOR min(32, remaining) bytes of input with keystream
    mov rcx, r15
    cmp rcx, 32
    jbe .xor_ok
    mov rcx, 32
.xor_ok:
    lea rsi, [rel keystream_blk]
    mov rdi, rbp
    mov rdx, r14
    push rcx
.xor_byte:
    mov al, [rdx]
    xor al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdx
    inc rdi
    dec ecx
    jnz .xor_byte
    pop rcx

    add r14, rcx
    add rbp, rcx
    sub r15, rcx
    inc ebx
    jmp .ctr_loop

.ctr_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; cipher_crypt — version-aware entry cipher wrapper.
; Args: same as ctr_crypt (rdi=key, rsi=iv, rdx=in, rcx=len, r8=out).
;   v1/v2/v3: forwards to ctr_crypt (SHA-256 keystream).
;   v4:       in-memory entries are plaintext (whole body is AEAD'd at
;             file boundary). This becomes a plain memcpy.
; ════════════════════════════════════════════════════════════════
ctr_crypt:
    cmp     word [rel g_vault_version], VAULT_VERSION_V4
    je      .cc_v4
    jmp     ctr_crypt_raw
.cc_v4:
    push    rsi
    push    rdi
    mov     rsi, rdx
    mov     rdi, r8
    rep     movsb
    pop     rdi
    pop     rsi
    ret

; ════════════════════════════════════════════════════════════════
; ChaCha20 block (RFC 8439 §2.3)
;   rdi = key (32 bytes, treated as 8 LE u32)
;   rsi = nonce (12 bytes, treated as 3 LE u32)
;   edx = block counter (u32)
;   r8  = output buffer (64 bytes, LE serialization)
;
; Builds initial state, copies to working state, runs 20 rounds
; (10 double-rounds = column QRs + diagonal QRs), then adds the
; original state into the working state and writes 16 LE u32s.
; ════════════════════════════════════════════════════════════════

%macro CHACHA_QR 4
    ; Quarter-round on dwords [rbx + %1*4], [rbx + %2*4],
    ; [rbx + %3*4], [rbx + %4*4]. Uses eax as scratch.
    mov     eax, [rbx + %2*4]
    add     [rbx + %1*4], eax
    mov     eax, [rbx + %1*4]
    xor     [rbx + %4*4], eax
    rol     dword [rbx + %4*4], 16

    mov     eax, [rbx + %4*4]
    add     [rbx + %3*4], eax
    mov     eax, [rbx + %3*4]
    xor     [rbx + %2*4], eax
    rol     dword [rbx + %2*4], 12

    mov     eax, [rbx + %2*4]
    add     [rbx + %1*4], eax
    mov     eax, [rbx + %1*4]
    xor     [rbx + %4*4], eax
    rol     dword [rbx + %4*4], 8

    mov     eax, [rbx + %4*4]
    add     [rbx + %3*4], eax
    mov     eax, [rbx + %3*4]
    xor     [rbx + %2*4], eax
    rol     dword [rbx + %2*4], 7
%endmacro

chacha20_block:
    push    rbx
    push    r12
    push    r13

    mov     r12, rdi                ; key ptr
    mov     r13, r8                 ; output ptr

    ; ── Build initial state in chacha_state ─────────────────
    lea     rbx, [rel chacha_state]

    ; Constants "expand 32-byte k" as 4 LE u32 (RFC §2.3)
    mov     dword [rbx + 0*4], 0x61707865
    mov     dword [rbx + 1*4], 0x3320646e
    mov     dword [rbx + 2*4], 0x79622d32
    mov     dword [rbx + 3*4], 0x6b206574

    ; Key: 8 LE u32 copied straight from rdi (x86 loads are LE)
    mov     eax, [r12 + 0]
    mov     [rbx + 4*4], eax
    mov     eax, [r12 + 4]
    mov     [rbx + 5*4], eax
    mov     eax, [r12 + 8]
    mov     [rbx + 6*4], eax
    mov     eax, [r12 + 12]
    mov     [rbx + 7*4], eax
    mov     eax, [r12 + 16]
    mov     [rbx + 8*4], eax
    mov     eax, [r12 + 20]
    mov     [rbx + 9*4], eax
    mov     eax, [r12 + 24]
    mov     [rbx + 10*4], eax
    mov     eax, [r12 + 28]
    mov     [rbx + 11*4], eax

    ; Counter and nonce
    mov     [rbx + 12*4], edx
    mov     eax, [rsi + 0]
    mov     [rbx + 13*4], eax
    mov     eax, [rsi + 4]
    mov     [rbx + 14*4], eax
    mov     eax, [rsi + 8]
    mov     [rbx + 15*4], eax

    ; ── Copy state → work (16 dwords) ────────────────────────
    lea     rdi, [rel chacha_work]
    mov     rsi, rbx
    mov     ecx, 16
    rep     movsd

    ; Subsequent QRs operate on chacha_work via rbx
    lea     rbx, [rel chacha_work]

    ; ── 20 rounds = 10 double-rounds ─────────────────────────
    mov     ecx, 10
.round_loop:
    CHACHA_QR 0, 4,  8, 12
    CHACHA_QR 1, 5,  9, 13
    CHACHA_QR 2, 6, 10, 14
    CHACHA_QR 3, 7, 11, 15
    CHACHA_QR 0, 5, 10, 15
    CHACHA_QR 1, 6, 11, 12
    CHACHA_QR 2, 7,  8, 13
    CHACHA_QR 3, 4,  9, 14
    dec     ecx
    jnz     .round_loop

    ; ── work[i] += state[i]; store as LE u32 to output ───────
    lea     rsi, [rel chacha_state]
    mov     rdi, r13
    xor     ecx, ecx
.add_loop:
    mov     eax, [rbx + rcx*4]
    add     eax, [rsi + rcx*4]
    mov     [rdi + rcx*4], eax      ; x86 store is already LE
    inc     ecx
    cmp     ecx, 16
    jne     .add_loop

    pop     r13
    pop     r12
    pop     rbx
    ret

; ════════════════════════════════════════════════════════════════
; ChaCha20 stream XOR (RFC 8439 §2.4)
;   rdi = key (32)
;   rsi = nonce (12)
;   edx = initial block counter (u32)
;   rcx = input ptr
;   r8  = length in bytes
;   r9  = output ptr
;
; Generates keystream blocks via chacha20_block and XORs them
; into the input. Counter increments per 64-byte block.
; ════════════════════════════════════════════════════════════════
chacha20_xor:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp

    mov     rbx, rdi                ; key
    mov     r12, rsi                ; nonce
    mov     r13d, edx               ; counter
    mov     r14, rcx                ; input
    mov     r15, r8                 ; remaining length
    mov     rbp, r9                 ; output

.blk_loop:
    test    r15, r15
    jz      .blk_done

    ; Generate one 64-byte keystream block at chacha_block
    mov     rdi, rbx
    mov     rsi, r12
    mov     edx, r13d
    lea     r8, [rel chacha_block]
    call    chacha20_block

    ; XOR min(64, remaining) bytes
    mov     rcx, 64
    cmp     r15, 64
    jae     .xor_full
    mov     rcx, r15
.xor_full:
    lea     rsi, [rel chacha_block]
    mov     rdi, rbp
    mov     rdx, r14
    push    rcx
.xor_byte:
    mov     al, [rdx]
    xor     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdx
    inc     rdi
    dec     rcx
    jnz     .xor_byte
    pop     rcx

    add     r14, rcx
    add     rbp, rcx
    sub     r15, rcx
    inc     r13d
    jmp     .blk_loop

.blk_done:
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ════════════════════════════════════════════════════════════════
; Poly1305 internal: h ← (h * r) mod (2^130 - 5)
; Reads poly_h (3 u64), poly_r (2 u64). Writes poly_h.
; Clobbers rax, rcx, rdx, rsi, rdi, rbx, r12-r15. Preserves rbp.
; Schoolbook 3x2 multiply → 5 limbs → fold high bits ×5.
; ════════════════════════════════════════════════════════════════
poly1305_mul:
    ; T0=rbx, T1=r12, T2=r13, T3=r14, T4=r15
    xor     r15d, r15d              ; T4

    ; --- h0 * r0 ---
    mov     rax, [rel poly_h + 0]
    mul     qword [rel poly_r + 0]
    mov     rbx, rax                ; T0
    mov     r12, rdx                ; T1

    ; --- h0 * r1 ---
    mov     rax, [rel poly_h + 0]
    mul     qword [rel poly_r + 8]
    xor     r13d, r13d              ; T2 = 0
    add     r12, rax
    adc     r13, rdx

    ; --- h1 * r0 ---
    mov     rax, [rel poly_h + 8]
    mul     qword [rel poly_r + 0]
    xor     r14d, r14d              ; T3 = 0
    add     r12, rax
    adc     r13, rdx
    adc     r14, 0

    ; --- h1 * r1 ---
    mov     rax, [rel poly_h + 8]
    mul     qword [rel poly_r + 8]
    add     r13, rax
    adc     r14, rdx
    adc     r15, 0

    ; --- h2 * r0 ---
    mov     rax, [rel poly_h + 16]
    mul     qword [rel poly_r + 0]
    add     r13, rax
    adc     r14, rdx
    adc     r15, 0

    ; --- h2 * r1 ---
    mov     rax, [rel poly_h + 16]
    mul     qword [rel poly_r + 8]
    add     r14, rax
    adc     r15, rdx

    ; ── Reduce: fold bits ≥ 130 back as ×5 ──────────────────
    ; Result so far: (T4:T3:T2:T1:T0) at positions 0,64,128,192,256
    ; Low part (bits 0..129): T0, T1, T2 & 3
    ; High part (bits 130..): H0=(T3<<62)|(T2>>2), H1=(T4<<62)|(T3>>2), H2=T4>>2

    mov     rcx, r13
    and     rcx, 3                  ; rcx = h2_low = T2 & 3

    shrd    r13, r14, 2             ; r13 = H0 = (T3:T2) >> 2 low 64
    shrd    r14, r15, 2             ; r14 = H1 = (T4:T3) >> 2 low 64
    shr     r15, 2                  ; r15 = H2 = T4 >> 2

    mov     rsi, 5

    ; T0 += (5*H0).lo;  T1 += (5*H0).hi (+ carry); h2_low += carry
    mov     rax, r13
    mul     rsi
    add     rbx, rax
    adc     r12, rdx
    adc     rcx, 0

    ; T1 += (5*H1).lo;  h2_low += (5*H1).hi (+ carry)
    mov     rax, r14
    mul     rsi
    add     r12, rax
    adc     rcx, rdx

    ; h2_low += 5*H2  (5*H2 is small; H2 < 2^4 in practice)
    mov     rax, r15
    mul     rsi
    add     rcx, rax
    ; rdx assumed 0 here (H2*5 < 2^7); not folding further at this step

    ; ── Second fold: rcx (h2) may exceed 2 bits ─────────────
    mov     rax, rcx
    shr     rax, 2                  ; rax = h2_overflow
    and     rcx, 3                  ; rcx = final h2 (low 2 bits)
    lea     rdx, [rax + rax*4]      ; rdx = 5 * overflow
    add     rbx, rdx
    adc     r12, 0
    adc     rcx, 0

    ; Store
    mov     [rel poly_h + 0], rbx
    mov     [rel poly_h + 8], r12
    mov     [rel poly_h + 16], rcx
    ret

; ════════════════════════════════════════════════════════════════
; Poly1305 streaming API + one-shot wrapper (RFC 8439 §2.5)
; ════════════════════════════════════════════════════════════════

; --- poly1305_init(rdi = key 32) -------------------------------
poly1305_init:
    mov     rax, [rdi + 0]
    mov     rdx, [rdi + 8]
    mov     rcx, 0x0ffffffc0fffffff
    and     rax, rcx
    mov     rcx, 0x0ffffffc0ffffffc
    and     rdx, rcx
    mov     [rel poly_r + 0], rax
    mov     [rel poly_r + 8], rdx
    mov     rax, [rdi + 16]
    mov     rdx, [rdi + 24]
    mov     [rel poly_s + 0], rax
    mov     [rel poly_s + 8], rdx
    xor     eax, eax
    mov     [rel poly_h + 0], rax
    mov     [rel poly_h + 8], rax
    mov     [rel poly_h + 16], rax
    ret

; --- poly1305_blocks(rdi = msg, rsi = num_blocks) --------------
; Process N complete 16-byte blocks (each with hi-bit 0x01 << 128).
poly1305_blocks:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp
    mov     rbp, rdi
    mov     r8,  rsi
.pb_loop:
    test    r8, r8
    jz      .pb_done
    mov     rax, [rbp + 0]
    mov     rdx, [rbp + 8]
    add     [rel poly_h + 0], rax
    adc     [rel poly_h + 8], rdx
    adc     qword [rel poly_h + 16], 1
    call    poly1305_mul
    add     rbp, 16
    dec     r8
    jmp     .pb_loop
.pb_done:
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; --- poly1305_partial(rdi = msg, rsi = partial_len 1..15) ------
; Process one partial trailing block: zero-pad then set 0x01 at index partial_len.
poly1305_partial:
    test    rsi, rsi
    jz      .pp_skip
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp

    xor     eax, eax
    mov     [rel poly_buf + 0], rax
    mov     [rel poly_buf + 8], rax

    lea     rbp, [rel poly_buf]
    mov     rcx, rsi
.pp_copy:
    test    rcx, rcx
    jz      .pp_set
    mov     al, [rdi]
    mov     [rbp], al
    inc     rdi
    inc     rbp
    dec     rcx
    jmp     .pp_copy
.pp_set:
    mov     byte [rbp], 0x01
    mov     rax, [rel poly_buf + 0]
    mov     rdx, [rel poly_buf + 8]
    add     [rel poly_h + 0], rax
    adc     [rel poly_h + 8], rdx
    adc     qword [rel poly_h + 16], 0
    call    poly1305_mul

    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
.pp_skip:
    ret

; --- poly1305_pad_block(rdi = msg, rsi = len 1..15) ------------
; AEAD-style trailing block: zero-pad to 16, process as a FULL
; block (hi-bit = 1<<128). Used for aad/ct final partial bytes
; in chacha20_poly1305 seal/open.
poly1305_pad_block:
    test    rsi, rsi
    jz      .pad_skip
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp

    xor     eax, eax
    mov     [rel poly_buf + 0], rax
    mov     [rel poly_buf + 8], rax

    lea     rbp, [rel poly_buf]
    mov     rcx, rsi
.pad_copy:
    test    rcx, rcx
    jz      .pad_apply
    mov     al, [rdi]
    mov     [rbp], al
    inc     rdi
    inc     rbp
    dec     rcx
    jmp     .pad_copy
.pad_apply:
    mov     rax, [rel poly_buf + 0]
    mov     rdx, [rel poly_buf + 8]
    add     [rel poly_h + 0], rax
    adc     [rel poly_h + 8], rdx
    adc     qword [rel poly_h + 16], 1
    call    poly1305_mul

    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
.pad_skip:
    ret

; --- poly1305_finish(rdi = tag_out 16) -------------------------
poly1305_finish:
    push    rbx
    push    r12
    push    rdi                     ; save tag_out

    ; Reduce: fold any residual h2 bits ≥ 2 back via ×5
    mov     rcx, [rel poly_h + 16]
    mov     rax, rcx
    shr     rax, 2
    and     rcx, 3
    lea     rdx, [rax + rax*4]
    mov     rbx, [rel poly_h + 0]
    mov     r12, [rel poly_h + 8]
    add     rbx, rdx
    adc     r12, 0
    adc     rcx, 0

    ; Conditional subtract of p = 2^130 - 5
    mov     rax, rbx
    add     rax, 5
    mov     rdx, r12
    adc     rdx, 0
    mov     rsi, rcx
    adc     rsi, 0
    mov     rdi, rsi
    shr     rdi, 2                  ; nonzero = overflow past 2^130
    test    rdi, rdi
    jz      .pf_no_sub
    mov     rbx, rax
    mov     r12, rdx
.pf_no_sub:

    ; Add s, store low 128 bits as tag
    add     rbx, [rel poly_s + 0]
    adc     r12, [rel poly_s + 8]

    pop     rdi
    mov     [rdi + 0], rbx
    mov     [rdi + 8], r12
    pop     r12
    pop     rbx
    ret

; --- poly1305_mac(rdi = key, rsi = msg, rdx = len, rcx = tag) --
; One-shot wrapper.
poly1305_mac:
    push    rbx
    push    r12
    push    r13
    push    r14

    mov     rbx, rsi                ; msg ptr
    mov     r12, rdx                ; msg len
    mov     r13, rcx                ; tag_out
    mov     r14, rdi                ; key

    mov     rdi, r14
    call    poly1305_init

    mov     rdi, rbx
    mov     rsi, r12
    shr     rsi, 4                  ; full blocks
    call    poly1305_blocks

    mov     rax, r12
    and     rax, 15                 ; partial len
    test    rax, rax
    jz      .pm_no_partial
    mov     rdi, r12
    and     rdi, ~15
    add     rdi, rbx                ; ptr to start of partial
    mov     rsi, rax
    call    poly1305_partial
.pm_no_partial:

    mov     rdi, r13
    call    poly1305_finish

    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ════════════════════════════════════════════════════════════════
; ChaCha20-Poly1305 AEAD seal (RFC 8439 §2.8.1)
;   rdi = key (32)        rsi = nonce (12)
;   rdx = aad ptr         rcx = aad len
;   r8  = pt ptr          r9  = pt len
; Output: in-place encrypt at [r8..r8+pt_len], 16-byte tag in poly_tag.
;
; Construction:
;   otk        = chacha20_block(key, nonce, counter=0)[0..32]
;   ciphertext = chacha20_xor(key, nonce, counter=1, plaintext)
;   mac_data   = aad || pad16 || ct || pad16 || aad_len_le64 || ct_len_le64
;   tag        = poly1305(otk, mac_data)
; ════════════════════════════════════════════════════════════════
chacha20_poly1305_seal:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp

    mov     rbx, rdi                ; key
    mov     r12, rsi                ; nonce
    mov     r13, rdx                ; aad ptr
    mov     r14, rcx                ; aad len
    mov     r15, r8                 ; pt/ct ptr
    mov     rbp, r9                 ; pt len

    ; ── Derive OTK = first 32 bytes of chacha20_block(key, nonce, 0) ──
    mov     rdi, rbx
    mov     rsi, r12
    xor     edx, edx
    lea     r8, [rel chacha_block]
    call    chacha20_block
    mov     rax, [rel chacha_block + 0]
    mov     [rel poly_otk + 0], rax
    mov     rax, [rel chacha_block + 8]
    mov     [rel poly_otk + 8], rax
    mov     rax, [rel chacha_block + 16]
    mov     [rel poly_otk + 16], rax
    mov     rax, [rel chacha_block + 24]
    mov     [rel poly_otk + 24], rax

    ; ── Encrypt pt in place: chacha20_xor(key, nonce, ctr=1, pt, len, pt) ──
    mov     rdi, rbx
    mov     rsi, r12
    mov     edx, 1
    mov     rcx, r15
    mov     r8,  rbp
    mov     r9,  r15
    call    chacha20_xor

    ; ── Build MAC stream via Poly1305 ────────────────────────
    lea     rdi, [rel poly_otk]
    call    poly1305_init

    ; AAD full blocks
    mov     rdi, r13
    mov     rsi, r14
    shr     rsi, 4
    call    poly1305_blocks
    ; AAD partial
    mov     rax, r14
    and     rax, 15
    test    rax, rax
    jz      .seal_aad_done
    mov     rdi, r14
    and     rdi, -16
    add     rdi, r13
    mov     rsi, rax
    call    poly1305_pad_block
.seal_aad_done:

    ; CT full blocks
    mov     rdi, r15
    mov     rsi, rbp
    shr     rsi, 4
    call    poly1305_blocks
    ; CT partial
    mov     rax, rbp
    and     rax, 15
    test    rax, rax
    jz      .seal_ct_done
    mov     rdi, rbp
    and     rdi, -16
    add     rdi, r15
    mov     rsi, rax
    call    poly1305_pad_block
.seal_ct_done:

    ; Length block = aad_len_le64 || ct_len_le64 (one full Poly1305 block)
    mov     [rel poly_lens + 0], r14
    mov     [rel poly_lens + 8], rbp
    lea     rdi, [rel poly_lens]
    mov     esi, 1
    call    poly1305_blocks

    ; Finish → poly_tag
    lea     rdi, [rel poly_tag]
    call    poly1305_finish

    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ════════════════════════════════════════════════════════════════
; ChaCha20-Poly1305 AEAD open (RFC 8439 §2.8.1)
;   rdi = key (32)        rsi = nonce (12)
;   rdx = aad ptr         rcx = aad len
;   r8  = ct ptr          r9  = ct len
; Tag is expected at [r8 + r9 .. r8 + r9 + 16].
;
; Return: rax = 0 if tag valid (pt in [r8..r8+r9] after decrypt).
;         rax = -1 if tag mismatch (buffer left UNCHANGED).
;
; Tag verified first; decryption happens only on valid tag.
; Constant-time tag compare.
; ════════════════════════════════════════════════════════════════
chacha20_poly1305_open:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rbp

    mov     rbx, rdi                ; key
    mov     r12, rsi                ; nonce
    mov     r13, rdx                ; aad ptr
    mov     r14, rcx                ; aad len
    mov     r15, r8                 ; ct ptr
    mov     rbp, r9                 ; ct len

    ; ── 1. Derive OTK ────────────────────────────────────────
    mov     rdi, rbx
    mov     rsi, r12
    xor     edx, edx
    lea     r8, [rel chacha_block]
    call    chacha20_block
    mov     rax, [rel chacha_block + 0]
    mov     [rel poly_otk + 0], rax
    mov     rax, [rel chacha_block + 8]
    mov     [rel poly_otk + 8], rax
    mov     rax, [rel chacha_block + 16]
    mov     [rel poly_otk + 16], rax
    mov     rax, [rel chacha_block + 24]
    mov     [rel poly_otk + 24], rax

    ; ── 2. Compute MAC over received aad/ct/lens ─────────────
    lea     rdi, [rel poly_otk]
    call    poly1305_init

    mov     rdi, r13
    mov     rsi, r14
    shr     rsi, 4
    call    poly1305_blocks
    mov     rax, r14
    and     rax, 15
    test    rax, rax
    jz      .open_aad_done
    mov     rdi, r14
    and     rdi, -16
    add     rdi, r13
    mov     rsi, rax
    call    poly1305_pad_block
.open_aad_done:

    mov     rdi, r15
    mov     rsi, rbp
    shr     rsi, 4
    call    poly1305_blocks
    mov     rax, rbp
    and     rax, 15
    test    rax, rax
    jz      .open_ct_done
    mov     rdi, rbp
    and     rdi, -16
    add     rdi, r15
    mov     rsi, rax
    call    poly1305_pad_block
.open_ct_done:

    mov     [rel poly_lens + 0], r14
    mov     [rel poly_lens + 8], rbp
    lea     rdi, [rel poly_lens]
    mov     esi, 1
    call    poly1305_blocks

    lea     rdi, [rel poly_tag]
    call    poly1305_finish

    ; ── 3. Constant-time tag compare ─────────────────────────
    ; Expected tag at [r15 + rbp .. + 16]; computed in poly_tag.
    lea     rsi, [rel poly_tag]
    lea     rdi, [r15 + rbp]
    xor     eax, eax                ; accumulator (diff)
    xor     ecx, ecx
.open_cmp:
    mov     dl, [rsi + rcx]
    xor     dl, [rdi + rcx]
    or      al, dl
    inc     rcx
    cmp     rcx, 16
    jne     .open_cmp

    test    al, al
    jz      .open_decrypt

    ; Tag mismatch — return -1 without touching ct buffer
    mov     rax, -1
    jmp     .open_ret

.open_decrypt:
    ; ── 4. Decrypt in place ──────────────────────────────────
    mov     rdi, rbx
    mov     rsi, r12
    mov     edx, 1
    mov     rcx, r15
    mov     r8,  rbp
    mov     r9,  r15
    call    chacha20_xor
    xor     eax, eax                ; rax = 0 success

.open_ret:
    pop     rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ════════════════════════════════════════════════════════════════
; v4 file-format helpers
;
; Layout (offsets identical to v3 to minimize parser changes):
;   [0..7]    magic
;   [8..9]    version = 0x0004
;   [10..25]  salt
;   [26..29]  argon_iter
;   [30..41]  ChaCha20-Poly1305 nonce (12 bytes)
;   [42..61]  reserved (zero on write, ignored on read)
;   [62..N-16]  AEAD ciphertext of plaintext body
;             plaintext body = [entry_count(4)] || entries (same as v3)
;   [N-16..N] 16-byte Poly1305 tag
;
; AAD = bytes [0..62] (full header including reserved field).
; Key  = derived_key (post-keyfile if active).
; ════════════════════════════════════════════════════════════════

; seal_main_body_v4(rdi = plaintext body length)
; Reads:  vault_buf[62..62+plain_len], derived_key, vault_buf header [0..62]
; Writes: vault_buf[62..62+plain_len] (replaced by ciphertext),
;         vault_buf[62+plain_len..62+plain_len+16] (tag),
;         vault_buf[30..42] (fresh random nonce),
;         vault_file_size = 62 + plain_len + 16.
seal_main_body_v4:
    push    rbx
    push    r12
    push    r13
    mov     rbx, rdi                ; plain_len

    ; Fresh nonce → header nonce slot, zero pad the reserved region
    lea     rdi, [rel vault_buf + V4_NONCE_OFFSET]
    mov     esi, V4_NONCE_LEN
    call    get_random
    lea     rdi, [rel vault_buf + V4_RESERVED_OFFSET]
    mov     ecx, V4_RESERVED_LEN
    xor     al, al
    rep     stosb

    ; chacha20_poly1305_seal(derived_key, nonce, aad=header[0..V4_HEADER_LEN], pt=body, pt_len)
    lea     rdi, [rel derived_key]
    lea     rsi, [rel vault_buf + V4_NONCE_OFFSET]
    lea     rdx, [rel vault_buf]
    mov     ecx, V4_HEADER_LEN
    lea     r8,  [rel vault_buf + V4_HEADER_LEN]
    mov     r9,  rbx
    call    chacha20_poly1305_seal

    ; Append tag from poly_tag → vault_buf[V4_HEADER_LEN + plain_len ..]
    lea     rdi, [rel vault_buf + V4_HEADER_LEN]
    add     rdi, rbx
    lea     rsi, [rel poly_tag]
    mov     ecx, V4_TAG_LEN
    rep     movsb

    ; Update vault_file_size = header + plain_len + tag
    mov     rax, rbx
    add     rax, V4_HEADER_LEN + V4_TAG_LEN
    mov     [rel vault_file_size], rax

    pop     r13
    pop     r12
    pop     rbx
    ret

; open_main_body_v4 — decrypt body in place, verify tag.
; Reads:  vault_buf, vault_file_size, derived_key.
; Writes: vault_buf[62..N-16] becomes plaintext on success.
; Returns: rax = 0 on success, rax = -1 on tag mismatch / size error.
open_main_body_v4:
    ; ── Minimum file size for v4: header + entry_count(4) + tag ──
    mov     rax, [rel vault_file_size]
    cmp     rax, V4_HEADER_LEN + 4 + V4_TAG_LEN
    jl      .ob_fail

    ; ── Reject any nonzero byte in the reserved region [42..62] ──
    ;    These bytes are authenticated by AAD, but enforcing the
    ;    invariant here rejects malformed files before doing crypto
    ;    and locks the format against subtle metadata smuggling.
    ;    Use r10b as the accumulator (rax holds file_size — must not clobber).
    lea     rsi, [rel vault_buf + V4_RESERVED_OFFSET]
    mov     ecx, V4_RESERVED_LEN
    xor     r10d, r10d
.ob_check_zero:
    or      r10b, [rsi]
    inc     rsi
    dec     ecx
    jnz     .ob_check_zero
    test    r10b, r10b
    jnz     .ob_fail

    ; ── AEAD-open the body in place ──
    sub     rax, V4_HEADER_LEN + V4_TAG_LEN
    mov     r9, rax                     ; ct_len (≥ 4 by check above)

    push    r9
    lea     rdi, [rel derived_key]
    lea     rsi, [rel vault_buf + V4_NONCE_OFFSET]
    lea     rdx, [rel vault_buf]
    mov     ecx, V4_HEADER_LEN
    lea     r8,  [rel vault_buf + V4_HEADER_LEN]
    call    chacha20_poly1305_open
    pop     r9
    test    rax, rax
    jnz     .ob_fail

    ; Trim vault_file_size to header + plaintext body so entry-walk
    ; callers (recalc_and_save) land at the right offset.
    add     r9, V4_HEADER_LEN
    mov     [rel vault_file_size], r9
    xor     eax, eax
    ret

.ob_fail:
    mov     rax, -1
    ret

; ════════════════════════════════════════════════════════════════
; SHA-256 test command
; ════════════════════════════════════════════════════════════════
cmd_test_sha256:
    ; Header
    lea rdi, [rel test_sha_hdr]
    call print_str

    ; Test 1: SHA256("")
    lea rdi, [rel test_empty_msg]
    call print_str
    lea rdi, [rel buf]       ; empty input (0 bytes)
    xor esi, esi
    lea rdx, [rel hex_out]
    call sha256_hash
    lea rdi, [rel hex_out]
    mov esi, 32
    call print_hex
    ; Compare
    lea rdi, [rel hex_out]
    lea rsi, [rel expected_empty]
    mov ecx, 32
    call memcmp
    test eax, eax
    jz .t1_pass
    lea rdi, [rel test_fail]
    call print_str
    jmp .t2
.t1_pass:
    lea rdi, [rel test_pass]
    call print_str

.t2:
    ; Test 2: SHA256("abc")
    lea rdi, [rel test_abc_msg]
    call print_str
    lea rdi, [rel test_str_abc]
    mov esi, 3
    lea rdx, [rel hex_out]
    call sha256_hash
    lea rdi, [rel hex_out]
    mov esi, 32
    call print_hex
    lea rdi, [rel hex_out]
    lea rsi, [rel expected_abc]
    mov ecx, 32
    call memcmp
    test eax, eax
    jz .t2_pass
    lea rdi, [rel test_fail]
    call print_str
    jmp .t3
.t2_pass:
    lea rdi, [rel test_pass]
    call print_str

.t3:
    ; Test 3: SHA256("hello")
    lea rdi, [rel test_hello_msg]
    call print_str
    lea rdi, [rel test_str_hello]
    mov esi, 5
    lea rdx, [rel hex_out]
    call sha256_hash
    lea rdi, [rel hex_out]
    mov esi, 32
    call print_hex
    lea rdi, [rel hex_out]
    lea rsi, [rel expected_hello]
    mov ecx, 32
    call memcmp
    test eax, eax
    jz .t3_pass
    lea rdi, [rel test_fail]
    call print_str
    jmp .test_done
.t3_pass:
    lea rdi, [rel test_pass]
    call print_str

    ; Test 4: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    lea rdi, [rel test_sha1_abc_msg]
    call print_str
    lea rdi, [rel test_str_abc]
    mov esi, 3
    lea rdx, [rel hex_out]
    call sha1_hash
    lea rdi, [rel hex_out]
    mov esi, 20
    call print_hex
    lea rdi, [rel hex_out]
    lea rsi, [rel expected_sha1_abc]
    mov ecx, 20
    call memcmp
    test eax, eax
    jz .t4_pass
    lea rdi, [rel test_fail]
    call print_str
    jmp .test_done
.t4_pass:
    lea rdi, [rel test_pass]
    call print_str

.test_done:
    xor edi, edi
    call exit

; ════════════════════════════════════════════════════════════════
; ChaCha20 test command — runs RFC 8439 §2.3.2 block vector
; ════════════════════════════════════════════════════════════════
cmd_test_chacha20:
    lea     rdi, [rel test_cc_hdr]
    call    print_str

    lea     rdi, [rel test_cc_232]
    call    print_str

    ; chacha20_block(key=cc_232_key, nonce=cc_232_nonce, ctr=1, out=chacha_block)
    lea     rdi, [rel cc_232_key]
    lea     rsi, [rel cc_232_nonce]
    mov     edx, 1
    lea     r8,  [rel chacha_block]
    call    chacha20_block

    ; Print actual 64-byte block (hex)
    lea     rdi, [rel chacha_block]
    mov     esi, 64
    call    print_hex

    ; Compare to expected
    lea     rdi, [rel chacha_block]
    lea     rsi, [rel cc_232_expected]
    mov     ecx, 64
    call    memcmp
    test    eax, eax
    jz      .cc_pass
    lea     rdi, [rel test_fail]
    call    print_str
    jmp     .cc_done
.cc_pass:
    lea     rdi, [rel test_pass]
    call    print_str

    ; ── Poly1305 §2.5.2 ─────────────────────────────────────
    lea     rdi, [rel test_p_252]
    call    print_str

    lea     rdi, [rel p_252_key]
    lea     rsi, [rel p_252_msg]
    mov     rdx, P_252_MSG_LEN
    lea     rcx, [rel poly_tag]
    call    poly1305_mac

    lea     rdi, [rel poly_tag]
    mov     esi, 16
    call    print_hex

    lea     rdi, [rel poly_tag]
    lea     rsi, [rel p_252_expected]
    mov     ecx, 16
    call    memcmp
    test    eax, eax
    jz      .poly_pass
    lea     rdi, [rel test_fail]
    call    print_str
    jmp     .cc_done
.poly_pass:
    lea     rdi, [rel test_pass]
    call    print_str

    ; ── AEAD §2.8.2 ─────────────────────────────────────────
    lea     rdi, [rel test_a_282]
    call    print_str

    ; Copy plaintext into mutable scratch (seal encrypts in place)
    lea     rdi, [rel aead_scratch]
    lea     rsi, [rel a_282_pt]
    mov     ecx, A_282_PT_LEN
    rep     movsb

    lea     rdi, [rel a_282_key]
    lea     rsi, [rel a_282_nonce]
    lea     rdx, [rel a_282_aad]
    mov     ecx, A_282_AAD_LEN
    lea     r8,  [rel aead_scratch]
    mov     r9d, A_282_PT_LEN
    call    chacha20_poly1305_seal

    lea     rdi, [rel poly_tag]
    mov     esi, 16
    call    print_hex

    lea     rdi, [rel poly_tag]
    lea     rsi, [rel a_282_tag]
    mov     ecx, 16
    call    memcmp
    test    eax, eax
    jz      .aead_pass
    lea     rdi, [rel test_fail]
    call    print_str
    jmp     .cc_done
.aead_pass:
    lea     rdi, [rel test_pass]
    call    print_str

    ; ── AEAD round-trip: open(seal(pt)) == pt, tag valid ─────
    lea     rdi, [rel test_a_rt]
    call    print_str

    ; aead_scratch already holds ciphertext from seal; tag in poly_tag.
    ; Copy tag right after ct so open can read it: aead_scratch[114..130] = poly_tag
    lea     rdi, [rel aead_scratch + A_282_PT_LEN]
    lea     rsi, [rel poly_tag]
    mov     ecx, 16
    rep     movsb

    ; Open
    lea     rdi, [rel a_282_key]
    lea     rsi, [rel a_282_nonce]
    lea     rdx, [rel a_282_aad]
    mov     ecx, A_282_AAD_LEN
    lea     r8,  [rel aead_scratch]
    mov     r9d, A_282_PT_LEN
    call    chacha20_poly1305_open

    test    rax, rax
    jnz     .rt_fail
    ; Compare decrypted pt to original
    lea     rdi, [rel aead_scratch]
    lea     rsi, [rel a_282_pt]
    mov     ecx, A_282_PT_LEN
    call    memcmp
    test    eax, eax
    jnz     .rt_fail
    lea     rdi, [rel test_pass]
    call    print_str
    jmp     .rt_tamper
.rt_fail:
    lea     rdi, [rel test_fail]
    call    print_str
    jmp     .cc_done

.rt_tamper:
    ; ── AEAD tamper-rejection: flip one tag byte, expect failure ──
    lea     rdi, [rel test_a_tp]
    call    print_str

    ; Re-seal (since open just decrypted in place)
    lea     rdi, [rel aead_scratch]
    lea     rsi, [rel a_282_pt]
    mov     ecx, A_282_PT_LEN
    rep     movsb
    lea     rdi, [rel a_282_key]
    lea     rsi, [rel a_282_nonce]
    lea     rdx, [rel a_282_aad]
    mov     ecx, A_282_AAD_LEN
    lea     r8,  [rel aead_scratch]
    mov     r9d, A_282_PT_LEN
    call    chacha20_poly1305_seal
    ; Place tag, then flip one bit
    lea     rdi, [rel aead_scratch + A_282_PT_LEN]
    lea     rsi, [rel poly_tag]
    mov     ecx, 16
    rep     movsb
    xor     byte [rel aead_scratch + A_282_PT_LEN], 0x01

    lea     rdi, [rel a_282_key]
    lea     rsi, [rel a_282_nonce]
    lea     rdx, [rel a_282_aad]
    mov     ecx, A_282_AAD_LEN
    lea     r8,  [rel aead_scratch]
    mov     r9d, A_282_PT_LEN
    call    chacha20_poly1305_open
    cmp     rax, -1
    jne     .tp_fail
    lea     rdi, [rel test_pass]
    call    print_str
    jmp     .cc_done
.tp_fail:
    lea     rdi, [rel test_fail]
    call    print_str

.cc_done:
    xor     edi, edi
    call    exit

; ════════════════════════════════════════════════════════════════
; Vault Commands
; ════════════════════════════════════════════════════════════════

; ── vault init ───────────────────────────────────────────────
do_init:
    mov byte [rel init_pw_from_stdin], 0

    ; Parse init options: only --password-stdin is supported
    mov rcx, 2
.init_opt_loop:
    mov rax, [rel argc]
    cmp rcx, rax
    jge .init_opts_done
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel password_stdin_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .init_bad_opt
    mov byte [rel init_pw_from_stdin], 1
    inc rcx
    jmp .init_opt_loop
.init_bad_opt:
    lea rdi, [rel err_msg_bad_option]
    lea rsi, [rel err_code_bad_option]
    lea rdx, [rel msg_init_opt]
    mov ecx, 2
    call emit_err
.init_opts_done:

    ; Check if vault file already exists
    lea rdi, [rel vault_path]
    call file_exists
    test eax, eax
    jnz .init_exists

    ; Create ~/.vault directory
    lea rdi, [rel vault_path]
    call get_dir_part       ; rax = length up to last /
    push rax
    lea rdi, [rel vault_path]
    add rdi, rax
    mov byte [rdi], 0       ; temporarily null-terminate at dir
    lea rdi, [rel vault_path]
    mov esi, 0o700
    mov eax, SYS_MKDIR
    syscall
    pop rax
    lea rdi, [rel vault_path]
    add rdi, rax
    mov byte [rdi], '/'     ; restore

    cmp byte [rel init_pw_from_stdin], 0
    je .init_prompt_passwords

    ; Non-interactive init: read one password line from stdin and reuse it as confirmation
    lea rdi, [rel prompt_empty]
    lea rsi, [rel master_pw]
    mov edx, 255
    call read_line
    push rax
    lea rsi, [rel master_pw]
    lea rdi, [rel master_pw2]
    call strcpy
    pop rcx
    push rcx
    jmp .init_compare

.init_prompt_passwords:
    ; Read master password
    lea rdi, [rel prompt_master]
    lea rsi, [rel master_pw]
    mov edx, 255
    call read_password
    push rax                ; save pw length

    ; Confirm
    lea rdi, [rel prompt_confirm]
    lea rsi, [rel master_pw2]
    mov edx, 255
    call read_password
    mov rcx, rax            ; confirm length

    ; Compare
.init_compare:
    pop rax                 ; pw length
    cmp rax, rcx
    jne .init_mismatch
    lea rdi, [rel master_pw]
    lea rsi, [rel master_pw2]
    mov ecx, eax
    call memcmp
    test eax, eax
    jnz .init_mismatch

    ; Get password length
    lea rdi, [rel master_pw]
    call strlen
    mov r15, rax            ; pw_len

    ; Generate salt from /dev/urandom
    lea rdi, [rel vault_salt]
    mov esi, SALT_LEN
    call get_random

    ; Derive key — choose KDF based on --argon2 flag
    cmp byte [rel argon2_use_argon2], 0
    je .init_pbkdf2

    ; Argon2id KDF
    lea rdi, [rel master_pw]
    mov rsi, r15
    lea rdx, [rel vault_salt]
    mov ecx, SALT_LEN
    lea r8, [rel derived_key]
    call argon2id_hash
    jmp .init_kdf_done

.init_pbkdf2:
    ; PBKDF2-SHA256
    lea rdi, [rel master_pw]
    mov rsi, r15
    lea rdx, [rel vault_salt]
    mov ecx, SALT_LEN
    mov r8, PBKDF2_ITER
    lea r9, [rel derived_key]
    call pbkdf2_sha256
.init_kdf_done:

    ; Apply keyfile if active
    cmp byte [rel keyfile_active], 0
    je .init_no_keyfile
    call apply_keyfile
.init_no_keyfile:

    ; Build vault file: header + 0 entries
    lea rdi, [rel vault_buf]

    ; Magic (8 bytes)
    lea rsi, [rel vault_magic]
    mov ecx, 8
    rep movsb

    ; Version (2 bytes) — v4 if --v4 was passed, else v3 default,
    ; else v1 if --pbkdf2 was passed explicitly.
    cmp byte [rel v4_flag], 0
    jne .init_ver_v4
    cmp byte [rel argon2_use_argon2], 0
    je .init_ver_pbkdf2
    mov word [rdi], VAULT_VERSION_V3
    jmp .init_ver_done
.init_ver_v4:
    mov word [rdi], VAULT_VERSION_V4
    jmp .init_ver_done
.init_ver_pbkdf2:
    mov word [rdi], VAULT_VERSION_PBKDF2
.init_ver_done:
    mov ax, [rdi]               ; version word we just wrote
    mov [rel g_vault_version], ax
    add rdi, 2                  ; advance past version

    ; Salt (16 bytes)
    lea rsi, [rel vault_salt]
    mov ecx, SALT_LEN
    rep movsb

    ; Iteration count (4 bytes)
    mov dword [rdi], PBKDF2_ITER
    add rdi, 4

    ; HMAC placeholder (32 bytes) — will be filled after
    push rdi                ; save HMAC position
    mov ecx, HMAC_LEN
    xor al, al
    rep stosb

    ; Entry count (4 bytes)
    mov dword [rdi], 0
    add rdi, 4

    ; Calculate data size (from after HMAC to end)
    lea rax, [rel vault_buf]
    sub rdi, rax
    mov r14, rdi            ; total file size

    ; Now compute HMAC over the data after the HMAC field
    ; HMAC covers: entry_count(4) + entries
    pop rdi                 ; HMAC position in buffer
    push rdi
    add rdi, HMAC_LEN       ; start of data to HMAC
    lea rax, [rel vault_buf]
    mov rsi, r14
    sub rsi, rdi
    add rsi, rax            ; length = total - offset_of_data
    ; Wait, let me recalc. Data to HMAC = from after HMAC to end
    lea rdx, [rel vault_buf]
    add rdx, r14            ; end of file
    sub rdx, rdi
    sub rdx, HMAC_LEN       ; this doesn't look right

    ; Integrity step. v1/v2: HMAC over [62..66] entry_count only. v3:
    ; HMAC over the 66-byte header with HMAC slot zeroed. v4: AEAD-seal
    ; the 4-byte plaintext body and append tag.
    movzx eax, word [rel vault_buf + 8]
    cmp eax, VAULT_VERSION_V4
    je .init_aead_v4
    cmp eax, VAULT_VERSION_V3
    je .init_hmac_v3

    ; Legacy v1/v2
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, 4
    lea r8, [rel vault_hmac]
    call hmac_sha256
    jmp .init_hmac_done

.init_hmac_v3:
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    mov rcx, 66
    lea r8, [rel vault_hmac]
    call hmac_sha256

.init_hmac_done:

    ; Copy HMAC into buffer at offset 30
    pop rdi                 ; was HMAC position, but let's just use offset
    lea rdi, [rel vault_buf]
    add rdi, 30
    lea rsi, [rel vault_hmac]
    mov ecx, HMAC_LEN
    rep movsb

    ; Write file (v1/v2/v3 = 66 bytes)
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, 66
    mov ecx, 0o600
    call write_file
    jmp .init_post_write

.init_aead_v4:
    pop rdi                  ; discard saved HMAC position
    ; Plaintext body = 4 bytes (entry_count=0 already at vault_buf+62).
    ; seal_main_body_v4 generates the nonce, encrypts in place, appends
    ; the tag, and sets vault_file_size = 82.
    mov rdi, 4
    call seal_main_body_v4

    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    mov edx, eax
    mov ecx, 0o600
    call write_file

.init_post_write:

    ; Zero master password
    lea rdi, [rel master_pw]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel master_pw2]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel derived_key]
    mov ecx, 32
    call zero_mem

    lea rdi, [rel msg_init_ok]
    call print_str
    xor edi, edi
    call exit

.init_exists:
    lea rdi, [rel err_msg_vault_exists]
    lea rsi, [rel err_code_vault_exists]
    lea rdx, [rel msg_init_exist]
    mov ecx, 1
    call emit_err

.init_mismatch:
    lea rdi, [rel master_pw]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel master_pw2]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel err_msg_pw_mismatch]
    lea rsi, [rel err_code_pw_mismatch]
    lea rdx, [rel msg_mismatch]
    mov ecx, 1
    call emit_err

; ── Common error handlers (global labels for cross-function jumps) ──
err_no_vault:
    lea rdi, [rel err_msg_no_vault]
    lea rsi, [rel err_code_no_vault]
    lea rdx, [rel msg_no_vault]
    mov ecx, 1
    call emit_err

err_need_name:
    lea rdi, [rel err_msg_need_name]
    lea rsi, [rel err_code_need_name]
    lea rdx, [rel msg_no_name]
    mov ecx, 1
    call emit_err

err_not_found:
    call zero_sensitive
    lea rdi, [rel err_msg_not_found]
    lea rsi, [rel err_code_not_found]
    lea rdx, [rel msg_not_found]
    mov ecx, 1
    call emit_err

err_entry_exists:
    call zero_sensitive
    lea rdi, [rel err_msg_entry_exists]
    lea rsi, [rel err_code_entry_exists]
    lea rdx, [rel msg_exists]
    mov ecx, 1
    call emit_err

err_list_empty:
    ; Empty vault is a successful, structured result — emit JSON empty array
    ; when --json, "(empty)" line to stderr otherwise. Exit 0.
    cmp byte [rel output_json], 0
    jne .ele_json
    call argv_scan_json_flag
    test eax, eax
    jnz .ele_json
    lea rdi, [rel msg_empty]
    call print_err
    xor edi, edi
    call exit
.ele_json:
    lea rdi, [rel json_empty_arr]
    call print_str
    xor edi, edi
    call exit

; ── vault list ───────────────────────────────────────────────
do_list:
    mov edi, 2
    call parse_output_flags

    ; Open vault (requires master password, verifies HMAC)
    call open_vault

    ; Parse entry count at offset 62
    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz .list_empty

    cmp byte [rel output_json], 0
    jne .list_json

    mov ecx, eax            ; entry count
    lea rsi, [rel vault_buf]
    add rsi, 66             ; skip header, point to first entry

.list_loop:
    test ecx, ecx
    jz .list_done
    push rcx
    push rsi

    ; Read name length (4 bytes)
    mov eax, [rsi]
    add rsi, 4

    ; Print name
    mov rdi, rsi
    push rax
    call print_n            ; print rax bytes from rdi
    lea rdi, [rel msg_newline]
    call print_str
    pop rax

    ; Skip past name + encrypted data
    pop rsi
    add rsi, 4              ; name_len field
    add rsi, rax            ; name bytes
    mov eax, [rsi]          ; encrypted data length
    add rsi, 4              ; enc_len field
    add rsi, IV_LEN         ; IV
    add rsi, rax            ; encrypted data

    pop rcx
    dec ecx
    jmp .list_loop

.list_done:
.list_exit:
    xor edi, edi
    call exit

.list_empty:
    cmp byte [rel output_json], 0
    je err_list_empty
    lea rdi, [rel json_empty_arr]
    call print_str
    xor edi, edi
    call exit

.list_json:
    mov r12d, eax
    mov al, '['
    call print_char
    lea rbx, [rel vault_buf]
    add rbx, 66
    mov r15d, 1
.list_json_loop:
    test r12d, r12d
    jz .list_json_done
    mov eax, [rbx]          ; name_len
    mov r13d, eax
    lea rsi, [rbx + 4]
    lea rdi, [rel entry_name]
    mov ecx, r13d
    rep movsb
    mov byte [rdi], 0

    cmp r15d, 1
    je .list_json_emit
    mov al, ','
    call print_char
.list_json_emit:
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov r15d, 0

    add rbx, 4
    add rbx, r13
    mov eax, [rbx]          ; encrypted data length
    add rbx, 4
    add rbx, IV_LEN
    add rbx, rax
    dec r12d
    jmp .list_json_loop
.list_json_done:
    mov al, ']'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    xor edi, edi
    call exit

; ── vault add <name> ─────────────────────────────────────────
do_add:
    ; Check argc >= 3
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    ; Get entry name from argv[2]
    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = source
    lea rdi, [rel entry_name]
    call strcpy

    ; Reset staged field state and parse add options
    lea rdi, [rel entry_user]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    lea rdi, [rel entry_pass]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    lea rdi, [rel entry_url]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    lea rdi, [rel entry_notes]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    lea rdi, [rel entry_totp]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    mov byte [rel add_user_provided], 0
    mov byte [rel add_url_provided], 0
    mov byte [rel add_notes_provided], 0
    mov byte [rel add_totp_provided], 0
    mov byte [rel add_pw_from_stdin], 0

    mov rcx, 3
.add_opt_loop:
    mov rax, [rel argc]
    cmp rcx, rax
    jge .add_opts_done
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]

    lea rsi, [rel password_stdin_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .check_username
    mov byte [rel add_pw_from_stdin], 1
    inc rcx
    jmp .add_opt_loop

.check_username:
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel username_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .check_url
    mov rax, [rel argc]
    lea rdx, [rcx + 1]
    cmp rdx, rax
    jge .add_missing_value
    mov rax, [rel argv]
    mov rsi, [rax + rdx*8]
    lea rdi, [rel entry_user]
    push rcx
    call strcpy
    pop rcx
    mov byte [rel add_user_provided], 1
    add rcx, 2
    jmp .add_opt_loop

.check_url:
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel url_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .check_notes
    mov rax, [rel argc]
    lea rdx, [rcx + 1]
    cmp rdx, rax
    jge .add_missing_value
    mov rax, [rel argv]
    mov rsi, [rax + rdx*8]
    lea rdi, [rel entry_url]
    push rcx
    call strcpy
    pop rcx
    mov byte [rel add_url_provided], 1
    add rcx, 2
    jmp .add_opt_loop

.check_notes:
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel notes_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .check_totp
    mov rax, [rel argc]
    lea rdx, [rcx + 1]
    cmp rdx, rax
    jge .add_missing_value
    mov rax, [rel argv]
    mov rsi, [rax + rdx*8]
    lea rdi, [rel entry_notes]
    push rcx
    call strcpy
    pop rcx
    mov byte [rel add_notes_provided], 1
    add rcx, 2
    jmp .add_opt_loop

.check_totp:
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel totp_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jnz .check_output_flags
    mov rax, [rel argc]
    lea rdx, [rcx + 1]
    cmp rdx, rax
    jge .add_missing_value
    mov rax, [rel argv]
    mov rsi, [rax + rdx*8]
    lea rdi, [rel entry_totp]
    push rcx
    call strcpy
    pop rcx
    mov byte [rel add_totp_provided], 1
    add rcx, 2
    jmp .add_opt_loop

.check_output_flags:
    ; Accept --raw / --json / --exact silently — they're handled later by
    ; emit_ok_simple via argv scan. Without this, an agent passing --json
    ; would hit "unsupported option".
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel raw_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jz .add_consume_one
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel json_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jz .add_consume_one
    mov rax, [rel argv]
    mov rdi, [rax + rcx*8]
    lea rsi, [rel exact_flag]
    push rcx
    call strcmp
    pop rcx
    test eax, eax
    jz .add_consume_one
    jmp .add_bad_opt
.add_consume_one:
    inc rcx
    jmp .add_opt_loop

.add_missing_value:
    lea rdi, [rel err_msg_missing_value]
    lea rsi, [rel err_code_missing_value]
    lea rdx, [rel msg_opt_value]
    mov ecx, 2
    call emit_err

.add_bad_opt:
    lea rdi, [rel err_msg_bad_option]
    lea rsi, [rel err_code_bad_option]
    lea rdx, [rel msg_add_opt]
    mov ecx, 2
    call emit_err

.add_opts_done:

    ; Read vault, verify master password
    call open_vault         ; derives key, verifies HMAC

    ; Check entry doesn't already exist
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz err_entry_exists

    ; Read only fields that were not provided as flags
    cmp byte [rel add_user_provided], 0
    jne .add_have_username
    lea rdi, [rel prompt_username]
    lea rsi, [rel entry_user]
    mov edx, 255
    call read_line
.add_have_username:

    cmp byte [rel add_pw_from_stdin], 0
    je .add_prompt_password
    lea rdi, [rel prompt_empty]
    lea rsi, [rel entry_pass]
    mov edx, 255
    call read_line
    jmp .add_have_password
.add_prompt_password:
    lea rdi, [rel prompt_password]
    lea rsi, [rel entry_pass]
    mov edx, 255
    call read_password
.add_have_password:

    cmp byte [rel add_url_provided], 0
    jne .add_have_url
    lea rdi, [rel prompt_url]
    lea rsi, [rel entry_url]
    mov edx, 255
    call read_line
.add_have_url:

    cmp byte [rel add_notes_provided], 0
    jne .add_have_notes
    lea rdi, [rel prompt_notes]
    lea rsi, [rel entry_notes]
    mov edx, 255
    call read_line
.add_have_notes:

    cmp byte [rel add_totp_provided], 0
    jne .add_have_totp
    lea rdi, [rel prompt_totp]
    lea rsi, [rel entry_totp]
    mov edx, 255
    call read_line
.add_have_totp:

    ; Pack entry data: username\0password\0url\0notes\0totp\0
    call pack_entry_data
    mov r14, rax            ; plaintext data length

    ; Generate IV
    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    ; Encrypt entry data
    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    ; Append entry to vault buffer, recompute HMAC, write back
    call append_entry_and_save

    ; Show password strength — skip in agent mode (--raw/--json) to keep stdout clean
    call argv_scan_exact_mode    ; reuses the same scan (covers --raw/--json/--exact)
    test eax, eax
    jnz .add_skip_strength
    lea rdi, [rel entry_pass]
    call print_strength
.add_skip_strength:

    ; Zero sensitive data
    call zero_sensitive

    lea rdi, [rel msg_added]
    call emit_ok_simple

; ── vault get <name> [field] ─────────────────────────────────
do_get:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    ; Reject "vault get --json" / "vault get --raw" etc. — argv[2] must be a name,
    ; not a flag. Without this, "--json" was being treated as an entry name and
    ; failing with not_found instead of need_name.
    mov rax, [rel argv]
    mov rdi, [rax+16]
    cmp byte [rdi], '-'
    jne .get_name_ok
    cmp byte [rdi+1], '-'
    jne .get_name_ok
    jmp err_need_name
.get_name_ok:

    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = source
    lea rdi, [rel entry_name]
    call strcpy

    mov byte [rel output_raw], 0
    mov byte [rel output_json], 0

    call open_vault

    ; Lookup: exact when --raw/--json/--exact is in argv (agent-safe contract);
    ; fuzzy otherwise (preserves human ergonomics).
    call argv_scan_exact_mode
    test eax, eax
    jnz .get_exact_lookup
    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    jmp .get_lookup_done
.get_exact_lookup:
    lea rdi, [rel entry_name]
    call find_entry
.get_lookup_done:
    test rax, rax
    jz err_not_found

    ; Update entry_name to the actual matched name
    mov rsi, rax
    mov edx, [rsi]
    add rsi, 4
    lea rdi, [rel entry_name]
    mov ecx, edx
    rep movsb
    mov byte [rdi], 0

    ; rax = pointer to entry in vault_buf
    ; Decrypt it
    mov rsi, rax
    call decrypt_entry      ; entry_user/pass/url/notes filled

    ; Check if field specified (argc >= 4)
    xor r12d, r12d          ; field pointer
    mov rax, [rel argc]
    cmp rax, 4
    jl .get_no_field

    mov rax, [rel argv]
    mov rdi, [rax+24]       ; argv[3]
    lea rsi, [rel raw_flag]
    call strcmp
    test eax, eax
    jz .get_no_field
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel json_flag]
    call strcmp
    test eax, eax
    jz .get_no_field

    ; If argv[3] starts with "--" but wasn't recognized, treat it as a flag
    ; for parse_output_flags so it can reject (rather than silently treating
    ; "--bogus" as a field name).
    mov rax, [rel argv]
    mov rdi, [rax+24]
    cmp byte [rdi], '-'
    jne .get_have_field
    cmp byte [rdi+1], '-'
    jne .get_have_field
    jmp .get_no_field
.get_have_field:
    mov rax, [rel argv]
    mov r12, [rax+24]       ; field argument
    mov edi, 4
    jmp .get_flags_only

.get_no_field:
    mov edi, 3

.get_flags_only:
    call parse_output_flags

    ; Get field name from argv[3]
    test r12, r12
    jz .get_all
    mov rdi, r12

    ; Check which field
    lea rsi, [rel field_username]
    call strcmp
    test eax, eax
    jz .get_user
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_password]
    call strcmp
    test eax, eax
    jz .get_pass
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_url]
    call strcmp
    test eax, eax
    jz .get_url
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_notes]
    call strcmp
    test eax, eax
    jz .get_notes
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_totp]
    call strcmp
    test eax, eax
    jz .get_totp
    ; Default: print all
    jmp .get_all

.get_user:
    cmp byte [rel output_json], 0
    je .get_user_plain
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_user]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_user_plain:
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_pass:
    cmp byte [rel output_json], 0
    je .get_pass_plain
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_pass]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_pass_plain:
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_url:
    cmp byte [rel output_json], 0
    je .get_url_plain
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_url]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_url_plain:
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_notes:
    cmp byte [rel output_json], 0
    je .get_notes_plain
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_notes]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_notes_plain:
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_totp:
    cmp byte [rel output_json], 0
    je .get_totp_plain
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_totp]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_totp_plain:
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_all:
    cmp byte [rel output_json], 0
    je .get_all_check_raw
    mov al, '{'
    call print_char
    lea rdi, [rel entry_name]
    call print_json_quoted
    mov al, ':'
    call print_char
    mov al, '{'
    call print_char
    lea rdi, [rel field_username]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_user]
    call print_json_quoted
    mov al, ','
    call print_char
    lea rdi, [rel field_password]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_pass]
    call print_json_quoted
    mov al, ','
    call print_char
    lea rdi, [rel field_url]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_url]
    call print_json_quoted
    mov al, ','
    call print_char
    lea rdi, [rel field_notes]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_notes]
    call print_json_quoted
    mov al, ','
    call print_char
    lea rdi, [rel field_totp]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel entry_totp]
    call print_json_quoted
    mov al, '}'
    call print_char
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_all_check_raw:
    cmp byte [rel output_raw], 0
    je .get_all_plain
    lea rdi, [rel entry_name]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_user]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_pass]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_url]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_notes]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done
.get_all_plain:
    lea rdi, [rel label_name]
    call print_str
    lea rdi, [rel entry_name]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_user]
    call print_str
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_pass]
    call print_str
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_url]
    call print_str
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_notes]
    call print_str
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    cmp byte [rel entry_totp], 0
    je .get_done
    lea rdi, [rel label_totp2]
    call print_str
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

.get_done:
    call zero_sensitive
    xor edi, edi
    call exit

; ── vault gen <name> [length] ────────────────────────────────
do_gen:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = source
    lea rdi, [rel entry_name]
    call strcpy

    ; Get length from argv[3] or config or default
    mov r15d, [rel config_gen_len]
    test r15d, r15d
    jnz .gen_has_default
    mov r15, gen_default_len
.gen_has_default:
    mov rax, [rel argc]
    cmp rax, 4
    jl .gen_use_default
    mov rax, [rel argv]
    mov rdi, [rax+24]
    call atoi
    test eax, eax
    jz .gen_use_default
    cmp eax, 128
    jg .gen_use_default
    mov r15d, eax
.gen_use_default:

    call open_vault

    ; Check entry doesn't exist
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz err_entry_exists

    ; Generate random password
    lea rdi, [rel entry_pass]
    mov rsi, r15
    call gen_password

    ; Set other fields empty
    mov byte [rel entry_user], 0
    mov byte [rel entry_url], 0
    mov byte [rel entry_notes], 0
    mov byte [rel entry_totp], 0

    ; Pack and encrypt
    call pack_entry_data
    mov r14, rax

    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save

    ; Print the generated password
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    call zero_sensitive
    xor edi, edi
    call exit

; ── vault rm <name> ──────────────────────────────────────────
do_rm:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault

    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jz err_not_found

    ; rax = pointer to entry start in vault_buf
    ; Calculate entry size and remove it
    mov rsi, rax
    call get_entry_size     ; rax = total entry size
    mov rcx, rax            ; entry size

    ; Calculate how much data is after this entry
    mov rdi, rsi            ; entry start
    add rsi, rcx            ; past this entry
    lea rdx, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdx, rax            ; end of data
    sub rdx, rsi            ; bytes after entry
    mov rcx, rdx
    ; memmove: copy from rsi to rdi, rcx bytes
    rep movsb

    ; Decrease entry count
    lea rdi, [rel vault_buf]
    dec dword [rdi + 62]

    ; Decrease file size
    mov rax, [rel vault_file_size]
    ; recalculate from scratch
    call recalc_and_save

    call zero_sensitive
    lea rdi, [rel msg_removed]
    call emit_ok_simple

; ── vault export ─────────────────────────────────────────────
do_export:
    call open_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]     ; entry count
    test eax, eax
    jz err_list_empty

    mov ecx, eax
    add rsi, 66             ; first entry

.export_loop:
    test ecx, ecx
    jz .export_done
    push rcx
    push rsi

    ; Read and print name
    mov eax, [rsi]          ; name_len
    add rsi, 4
    push rax
    push rsi                ; save name ptr

    ; Decrypt this entry
    pop rsi
    push rsi
    pop rdi                 ; name ptr
    pop rax                 ; name_len
    push rax
    push rdi

    ; We need to pass entry pointer (at name_len field)
    mov rsi, [rsp + 16]     ; original rsi (entry start)
    call decrypt_entry

    ; Print: name<tab>username<tab>password<tab>url<tab>notes
    mov rsi, [rsp + 16]     ; entry start
    mov eax, [rsi]          ; name_len
    add rsi, 4              ; name data
    mov rdi, rsi
    push rax
    call print_n
    mov al, 9               ; tab
    call print_char
    pop rax

    lea rdi, [rel entry_user]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_pass]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_url]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_notes]
    call print_str
    mov al, 9
    call print_char
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    pop rdi                 ; name ptr (discard)
    pop rax                 ; name_len (discard)

    ; Advance to next entry
    pop rsi                 ; entry start
    mov eax, [rsi]          ; name_len
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]          ; enc_data_len
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax

    pop rcx
    dec ecx
    jmp .export_loop

.export_done:
    call zero_sensitive
    xor edi, edi
    call exit

; ── vault import [--bitwarden|--keepass] <file> ──────────────
do_import:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    ; Check for --bitwarden flag
    mov rax, [rel argv]
    mov rdi, [rax+16]       ; argv[2]
    lea rsi, [rel import_bw_flag]
    call strcmp
    test eax, eax
    jz do_import_bitwarden

    ; Check for --keepass flag
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel import_kp_flag]
    call strcmp
    test eax, eax
    jz do_import_keepass

    ; Default: tab-separated format
    mov rax, [rel argv]
    mov rdi, [rax+16]       ; argv[2] = filename
    push rdi

    call open_vault

    ; Read import file
    pop rdi
    lea rsi, [rel buf]
    mov edx, BUF_SIZE - 1
    call read_file
    test rax, rax
    jz .import_done_count

    mov r15, rax
    lea r12, [rel buf]
    xor r13d, r13d

.import_line:
    ; Find end of line or end of buffer
    mov rdi, r12
    lea rax, [rel buf]
    add rax, r15
    cmp rdi, rax
    jge .import_done_count

    ; Parse tab-separated: name\tusername\tpassword\turl\tnotes\n
    ; Copy name
    lea rdi, [rel entry_name]
    mov rsi, r12
    call copy_until_tab     ; rax = bytes consumed (including tab)
    add r12, rax

    ; Copy username
    lea rdi, [rel entry_user]
    mov rsi, r12
    call copy_until_tab
    add r12, rax

    ; Copy password
    lea rdi, [rel entry_pass]
    mov rsi, r12
    call copy_until_tab
    add r12, rax

    ; Copy url
    lea rdi, [rel entry_url]
    mov rsi, r12
    call copy_until_tab
    add r12, rax

    ; Copy notes (tab or newline)
    lea rdi, [rel entry_notes]
    mov rsi, r12
    call copy_until_tab
    add r12, rax

    ; Copy TOTP if present (until newline), else empty
    mov byte [rel entry_totp], 0
    ; Check if we hit a newline (copy_until_tab stops at tab or newline)
    cmp byte [r12 - 1], 10      ; did we stop at newline?
    je .import_no_totp
    lea rdi, [rel entry_totp]
    mov rsi, r12
    call copy_until_newline
    add r12, rax
.import_no_totp:

    ; Check name is non-empty
    cmp byte [rel entry_name], 0
    je .import_line

    ; Check not duplicate
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz .import_line        ; skip duplicates

    ; Pack entry data (includes totp field)
    call pack_entry_data
    mov r14, rax

    ; Generate IV and encrypt
    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save
    inc r13d
    jmp .import_line

.import_done_count:
    ; Print count
    mov eax, r13d
    lea rdi, [rel numbuf]
    call itoa
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_imported]
    call print_str

    call zero_sensitive
    xor edi, edi
    call exit

; ── Bitwarden JSON import ─────────────────────────────────────
do_import_bitwarden:
    mov rax, [rel argc]
    cmp rax, 4
    jl err_need_name

    mov rax, [rel argv]
    mov rdi, [rax+24]       ; argv[3] = filename
    push rdi
    call open_vault
    pop rdi

    lea rsi, [rel buf]
    mov edx, BUF_SIZE - 1
    call read_file
    test rax, rax
    jz .bw_done

    ; Null-terminate
    lea rdi, [rel buf]
    mov byte [rdi + rax], 0
    lea r12, [rel buf]      ; current scan position
    xor r13d, r13d          ; import count

.bw_scan:
    ; Find next "name" key — start of a new item
    mov rdi, r12
    lea rsi, [rel json_name]
    call json_find_key
    test rax, rax
    jz .bw_done
    mov r12, rax

    ; Extract name value
    mov rdi, r12
    lea rsi, [rel entry_name]
    call json_extract_string_value
    test rax, rax
    jz .bw_scan
    mov r12, rax

    cmp byte [rel entry_name], 0
    je .bw_scan

    ; Clear fields
    mov byte [rel entry_user], 0
    mov byte [rel entry_pass], 0
    mov byte [rel entry_url], 0
    mov byte [rel entry_notes], 0
    mov byte [rel entry_totp], 0

    ; Extract username (search forward from current position)
    mov rdi, r12
    lea rsi, [rel json_username]
    call json_find_key
    test rax, rax
    jz .bw_store
    mov rdi, rax
    lea rsi, [rel entry_user]
    call json_extract_string_value

    ; Extract password
    mov rdi, r12
    lea rsi, [rel json_password]
    call json_find_key
    test rax, rax
    jz .bw_store
    mov rdi, rax
    lea rsi, [rel entry_pass]
    call json_extract_string_value

    ; Extract uri
    mov rdi, r12
    lea rsi, [rel json_uri]
    call json_find_key
    test rax, rax
    jz .bw_store
    mov rdi, rax
    lea rsi, [rel entry_url]
    call json_extract_string_value

    ; Extract notes
    mov rdi, r12
    lea rsi, [rel json_notes]
    call json_find_key
    test rax, rax
    jz .bw_check_totp
    mov rdi, rax
    lea rsi, [rel entry_notes]
    call json_extract_string_value

.bw_check_totp:
    ; Extract totp into dedicated entry_totp field
    mov byte [rel entry_totp], 0
    mov rdi, r12
    lea rsi, [rel json_totp]
    call json_find_key
    test rax, rax
    jz .bw_store
    mov rdi, rax
    lea rsi, [rel entry_totp]
    call json_extract_string_value

.bw_store:
    ; Skip duplicates
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz .bw_scan

    call import_store_entry
    inc r13d
    jmp .bw_scan

.bw_done:
    mov eax, r13d
    lea rdi, [rel numbuf]
    call itoa
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_imported]
    call print_str
    call zero_sensitive
    xor edi, edi
    call exit

; ── KeePass CSV import ───────────────────────────────────────
do_import_keepass:
    mov rax, [rel argc]
    cmp rax, 4
    jl err_need_name

    mov rax, [rel argv]
    mov rdi, [rax+24]       ; argv[3] = filename
    push rdi
    call open_vault
    pop rdi

    lea rsi, [rel buf]
    mov edx, BUF_SIZE - 1
    call read_file
    test rax, rax
    jz .kp_done

    lea rdi, [rel buf]
    mov byte [rdi + rax], 0

    lea r12, [rel buf]
    xor r13d, r13d

    ; Skip header line
    mov rdi, r12
    call skip_to_newline
    test rax, rax
    jz .kp_done
    mov r12, rax

.kp_line:
    cmp byte [r12], 0
    je .kp_done
    ; Skip blank lines
    cmp byte [r12], 10
    jne .kp_parse
    inc r12
    jmp .kp_line

.kp_parse:
    ; KeePass: "Group","Title","Username","Password","URL","Notes"
    ; Skip Group
    mov rdi, r12
    lea rsi, [rel edit_buf]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; Title -> entry_name
    mov rdi, r12
    lea rsi, [rel entry_name]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; Username
    mov rdi, r12
    lea rsi, [rel entry_user]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; Password
    mov rdi, r12
    lea rsi, [rel entry_pass]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; URL
    mov rdi, r12
    lea rsi, [rel entry_url]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; Notes (last field)
    mov rdi, r12
    lea rsi, [rel entry_notes]
    call csv_extract_field
    test rax, rax
    jz .kp_done
    mov r12, rax

    ; TOTP not in KeePass CSV
    mov byte [rel entry_totp], 0

    ; Skip empty names
    cmp byte [rel entry_name], 0
    je .kp_line

    ; Skip duplicates
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz .kp_line

    call import_store_entry
    inc r13d
    jmp .kp_line

.kp_done:
    mov eax, r13d
    lea rdi, [rel numbuf]
    call itoa
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_imported]
    call print_str
    call zero_sensitive
    xor edi, edi
    call exit

; ── import_store_entry — pack, encrypt, store current entry fields ──
import_store_entry:
    push r14
    call pack_entry_data
    mov r14, rax

    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save
    pop r14
    ret

; ════════════════════════════════════════════════════════════════
; L2 Commands
; ════════════════════════════════════════════════════════════════

; ── vault show <name> — pretty-print entry ───────────────────
do_show:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault

    ; Find entry (fuzzy)
    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    test rax, rax
    jz err_not_found

    mov rsi, rax
    call decrypt_entry

    ; Pretty print with separator
    lea rdi, [rel msg_sep]
    call print_str

    lea rdi, [rel label_name]
    call print_str
    ; Print the matched name from vault, not search term
    ; rax from find_entry_fuzzy pointed to entry; name is at [entry+4]
    lea rdi, [rel entry_name]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_user]
    call print_str
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_pass]
    call print_str
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_url]
    call print_str
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel label_notes]
    call print_str
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    ; Show TOTP field if non-empty
    cmp byte [rel entry_totp], 0
    je .show_no_totp
    lea rdi, [rel label_totp2]
    call print_str
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
.show_no_totp:

    ; Password strength
    lea rdi, [rel entry_pass]
    call print_strength

    lea rdi, [rel msg_sep]
    call print_str

    call zero_sensitive
    xor edi, edi
    call exit

; ── vault search <term> — search entry names ─────────────────
do_search:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel search_term]
    call strcpy

    mov edi, 3
    call parse_output_flags

    call open_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz err_list_empty

    cmp byte [rel output_json], 0
    jne .search_json

    mov ecx, eax
    add rsi, 66
    xor r15d, r15d          ; match count

.search_loop:
    test ecx, ecx
    jz .search_done
    push rcx
    push rsi

    mov eax, [rsi]          ; name_len
    add rsi, 4              ; name data
    mov r13d, eax           ; save name_len (substr_match uses r13d)
    mov r14d, eax           ; also save in r14d for print

    ; Check if search_term is a substring of this name
    push rsi
    lea rdi, [rel search_term]
    ; rsi = name, r13d = name_len
    call substr_match
    pop rsi
    test eax, eax
    jz .search_skip

    ; Print matching name
    mov rdi, rsi
    mov eax, r14d
    call print_n
    lea rdi, [rel msg_newline]
    call print_str
.search_print_done:
    inc r15d

.search_skip:
    pop rsi
    mov eax, [rsi]          ; name_len
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]          ; enc_data_len
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax

    pop rcx
    dec ecx
    jmp .search_loop

.search_done:
    test r15d, r15d
    jnz .search_exit
    lea rdi, [rel msg_no_match]
    call print_str
.search_exit:
    xor edi, edi
    call exit

.search_json:
    mov ecx, [rsi + 62]
    add rsi, 66
    lea rbx, [rel buf]
    mov byte [rbx], '['
    inc rbx
    xor r14d, r14d          ; match count
.search_json_loop:
    test ecx, ecx
    jz .search_json_done
    push rcx
    push rsi

    mov eax, [rsi]          ; name_len
    add rsi, 4              ; name data
    mov r13d, eax
    mov r12d, eax
    push rsi
    lea rdi, [rel search_term]
    call substr_match
    pop rsi
    test eax, eax
    jz .search_json_skip

    test r14d, r14d
    jz .search_json_open
    mov byte [rbx], ','
    inc rbx
.search_json_open:
    mov byte [rbx], '"'
    inc rbx
.search_json_copy:
    test r12d, r12d
    jz .search_json_close
    mov al, [rsi]
    cmp al, '"'
    je .search_json_quote
    cmp al, 92
    je .search_json_bs
    cmp al, 10
    je .search_json_n
    cmp al, 13
    je .search_json_r
    cmp al, 9
    je .search_json_t
    mov [rbx], al
    inc rbx
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_quote:
    mov byte [rbx], 92
    mov byte [rbx + 1], '"'
    add rbx, 2
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_bs:
    mov byte [rbx], 92
    mov byte [rbx + 1], 92
    add rbx, 2
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_n:
    mov byte [rbx], 92
    mov byte [rbx + 1], 'n'
    add rbx, 2
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_r:
    mov byte [rbx], 92
    mov byte [rbx + 1], 'r'
    add rbx, 2
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_t:
    mov byte [rbx], 92
    mov byte [rbx + 1], 't'
    add rbx, 2
    inc rsi
    dec r12d
    jmp .search_json_copy
.search_json_close:
    mov byte [rbx], '"'
    inc rbx
    inc r14d

.search_json_skip:
    pop rsi
    mov eax, [rsi]          ; name_len
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]          ; enc_data_len
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax
    pop rcx
    dec ecx
    jmp .search_json_loop
.search_json_done:
    mov byte [rbx], ']'
    inc rbx
    mov byte [rbx], 10
    inc rbx
    mov byte [rbx], 0
    lea rdi, [rel buf]
    call print_str
    xor edi, edi
    call exit

; ── vault count — show total entries ─────────────────────────
do_count:
    mov edi, 2
    call parse_output_flags

    call open_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    cmp byte [rel output_json], 0
    je .count_check_raw
    lea rdi, [rel numbuf]
    call itoa
    mov al, '{'
    call print_char
    lea rdi, [rel json_key_count]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel numbuf]
    call print_str
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    xor edi, edi
    call exit
.count_check_raw:
    lea rdi, [rel numbuf]
    call itoa
    lea rdi, [rel numbuf]
    call print_str
    cmp byte [rel output_raw], 0
    jne .count_done
    lea rdi, [rel msg_entries]
    call print_str
.count_done:
    cmp byte [rel output_raw], 0
    je .count_exit
    lea rdi, [rel msg_newline]
    call print_str
.count_exit:
    xor edi, edi
    call exit

; ── vault edit <name> — edit entry fields ────────────────────
do_edit:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault

    ; Find entry (fuzzy)
    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    test rax, rax
    jz err_not_found

    ; Save entry pointer
    mov r15, rax            ; entry start in vault_buf
    mov rsi, rax
    call decrypt_entry

    ; Update entry_name to the actual matched name
    mov rsi, r15
    mov eax, [rsi]          ; name_len
    add rsi, 4
    lea rdi, [rel entry_name]
    mov ecx, eax
    rep movsb
    mov byte [rdi], 0

    ; Prompt for each field, showing current value
    ; Username
    lea rdi, [rel prompt_cur_user]
    call print_str
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel prompt_close]
    call print_str
    lea rsi, [rel edit_buf]
    mov edx, 255
    lea rdi, [rel edit_buf]    ; dummy prompt (empty)
    call read_line_noprompt
    cmp byte [rel edit_buf], 0
    je .edit_keep_user
    lea rsi, [rel edit_buf]
    lea rdi, [rel entry_user]
    call strcpy
.edit_keep_user:

    ; Password
    lea rdi, [rel prompt_cur_pass]
    call print_str
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel prompt_close]
    call print_str
    lea rsi, [rel edit_buf]
    mov edx, 255
    call read_line_noprompt
    cmp byte [rel edit_buf], 0
    je .edit_keep_pass
    lea rsi, [rel edit_buf]
    lea rdi, [rel entry_pass]
    call strcpy
.edit_keep_pass:

    ; URL
    lea rdi, [rel prompt_cur_url]
    call print_str
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel prompt_close]
    call print_str
    lea rsi, [rel edit_buf]
    mov edx, 255
    call read_line_noprompt
    cmp byte [rel edit_buf], 0
    je .edit_keep_url
    lea rsi, [rel edit_buf]
    lea rdi, [rel entry_url]
    call strcpy
.edit_keep_url:

    ; Notes
    lea rdi, [rel prompt_cur_note]
    call print_str
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel prompt_close]
    call print_str
    lea rsi, [rel edit_buf]
    mov edx, 255
    call read_line_noprompt
    cmp byte [rel edit_buf], 0
    je .edit_keep_notes
    lea rsi, [rel edit_buf]
    lea rdi, [rel entry_notes]
    call strcpy
.edit_keep_notes:

    ; TOTP
    lea rdi, [rel prompt_cur_totp]
    call print_str
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel prompt_close]
    call print_str
    lea rsi, [rel edit_buf]
    mov edx, 255
    call read_line_noprompt
    cmp byte [rel edit_buf], 0
    je .edit_keep_totp
    lea rsi, [rel edit_buf]
    lea rdi, [rel entry_totp]
    call strcpy
.edit_keep_totp:

    ; Remove old entry from vault_buf
    mov rsi, r15
    call get_entry_size
    mov rcx, rax

    mov rdi, r15
    lea rsi, [r15 + rcx]
    lea rdx, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdx, rax
    sub rdx, rsi
    push rcx
    mov rcx, rdx
    rep movsb
    pop rcx

    ; Decrease entry count and file size
    lea rdi, [rel vault_buf]
    dec dword [rdi + 62]
    mov rax, [rel vault_file_size]
    sub rax, rcx
    mov [rel vault_file_size], rax

    ; Re-add with new values (re-encrypt)
    call pack_entry_data
    mov r14, rax

    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save

    call zero_sensitive
    lea rdi, [rel msg_updated]
    call print_str
    xor edi, edi
    call exit

; ── vault clip <name> [field] — copy to clipboard, auto-clear ─
do_clip:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault

    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    test rax, rax
    jz err_not_found

    mov rsi, rax
    call decrypt_entry

    ; Default to password field, check argv[3]
    lea r15, [rel entry_pass]
    mov rax, [rel argc]
    cmp rax, 4
    jl .clip_do

    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_username]
    call strcmp
    test eax, eax
    jnz .clip_check_url
    lea r15, [rel entry_user]
    jmp .clip_do
.clip_check_url:
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_url]
    call strcmp
    test eax, eax
    jnz .clip_check_notes
    lea r15, [rel entry_url]
    jmp .clip_do
.clip_check_notes:
    mov rax, [rel argv]
    mov rdi, [rax+24]
    lea rsi, [rel field_notes]
    call strcmp
    test eax, eax
    jnz .clip_do
    lea r15, [rel entry_notes]

.clip_do:
    ; Fork: child sends to xclip, parent waits + clears
    ; Create pipe
    sub rsp, 16
    mov rdi, rsp            ; int pipefd[2]
    mov eax, SYS_PIPE
    syscall
    test eax, eax
    js .clip_err

    mov r12d, [rsp]         ; read end
    mov r13d, [rsp+4]       ; write end
    add rsp, 16

    ; Write field value to pipe write end
    mov rdi, r15
    call strlen
    mov r14d, eax           ; field len

    mov edi, r13d
    mov rsi, r15
    mov edx, r14d
    mov eax, SYS_WRITE
    syscall

    ; Close write end
    mov edi, r13d
    mov eax, SYS_CLOSE
    syscall

    ; Fork for xclip
    mov eax, SYS_FORK
    syscall
    test eax, eax
    js .clip_err
    jnz .clip_parent

    ; Child: dup2 pipe read to stdin, exec xclip
    mov edi, r12d
    xor esi, esi            ; stdin = 0
    mov eax, SYS_DUP2
    syscall
    mov edi, r12d
    mov eax, SYS_CLOSE
    syscall

    ; execve("/usr/bin/xclip", ["xclip", "-sel", "clip", NULL], NULL)
    lea rdi, [rel xclip_path]
    lea rsi, [rel xclip_argv]
    xor edx, edx
    mov eax, SYS_EXECVE
    syscall
    ; If exec failed, try xsel
    lea rdi, [rel xsel_path]
    lea rsi, [rel xsel_argv]
    xor edx, edx
    mov eax, SYS_EXECVE
    syscall
    ; Both failed
    mov edi, 1
    call exit

.clip_parent:
    mov r13d, eax           ; child pid
    mov edi, r12d
    mov eax, SYS_CLOSE
    syscall

    ; Wait for xclip child
    mov edi, r13d
    lea rsi, [rel numbuf]   ; status
    xor edx, edx
    xor r10d, r10d
    mov eax, SYS_WAIT4
    syscall

    lea rdi, [rel msg_copied]
    call print_str

    ; Fork again for auto-clear after 30 seconds
    mov eax, SYS_FORK
    syscall
    test eax, eax
    jnz .clip_exit          ; parent exits immediately

    ; Child: sleep 30s, then clear clipboard
    sub rsp, 16
    mov qword [rsp], 30     ; seconds
    mov qword [rsp+8], 0    ; nanoseconds
    mov rdi, rsp
    xor esi, esi
    mov eax, SYS_NANOSLEEP
    syscall
    add rsp, 16

    ; Clear: pipe empty string to xclip
    sub rsp, 16
    mov rdi, rsp
    mov eax, SYS_PIPE
    syscall
    mov r12d, [rsp]
    mov r13d, [rsp+4]
    add rsp, 16

    ; Close write end immediately (empty pipe)
    mov edi, r13d
    mov eax, SYS_CLOSE
    syscall

    mov eax, SYS_FORK
    syscall
    test eax, eax
    jnz .clip_clear_parent

    ; Grandchild: exec xclip with pipe read as stdin
    mov edi, r12d
    xor esi, esi
    mov eax, SYS_DUP2
    syscall
    mov edi, r12d
    mov eax, SYS_CLOSE
    syscall
    lea rdi, [rel xclip_path]
    lea rsi, [rel xclip_argv]
    xor edx, edx
    mov eax, SYS_EXECVE
    syscall
    mov edi, 1
    call exit

.clip_clear_parent:
    mov r13d, eax
    mov edi, r12d
    mov eax, SYS_CLOSE
    syscall
    mov edi, r13d
    lea rsi, [rel numbuf]
    xor edx, edx
    xor r10d, r10d
    mov eax, SYS_WAIT4
    syscall
    xor edi, edi
    call exit

.clip_exit:
    call zero_sensitive
    xor edi, edi
    call exit

.clip_err:
    lea rdi, [rel err_msg_no_xclip]
    lea rsi, [rel err_code_no_xclip]
    lea rdx, [rel msg_no_xclip]
    mov ecx, 1
    call emit_err

; ════════════════════════════════════════════════════════════════
; L3 Commands
; ════════════════════════════════════════════════════════════════

; ── vault verify — check vault integrity ─────────────────────
do_verify:
    mov edi, 2
    call parse_output_flags

    call open_vault
    ; If we get here, HMAC was verified successfully
    call zero_sensitive
    cmp byte [rel output_json], 0
    je .verify_check_raw
    lea rdi, [rel json_ok_true]
    call print_str
    xor edi, edi
    call exit
.verify_check_raw:
    cmp byte [rel output_raw], 0
    je .verify_plain
    lea rdi, [rel msg_ok_raw]
    call print_str
    xor edi, edi
    call exit
.verify_plain:
    lea rdi, [rel msg_verify_ok]
    call print_str
    xor edi, edi
    call exit

; ── vault backup — create timestamped backup ─────────────────
do_backup:
    ; Check vault exists
    lea rdi, [rel vault_path]
    call file_exists
    test eax, eax
    jz err_no_vault

    ; Build backup path: vault_path + ".bak." + timestamp
    lea rdi, [rel backup_path]
    lea rsi, [rel vault_path]
    call strcpy
    lea rdi, [rel backup_path]
    call strlen
    lea rdi, [rel backup_path]
    add rdi, rax

    ; Append ".bak."
    lea rsi, [rel backup_suffix]
    call strcpy
    lea rdi, [rel backup_path]
    call strlen
    lea rdi, [rel backup_path]
    add rdi, rax

    ; Get timestamp (seconds since epoch)
    sub rsp, 16
    xor edi, edi            ; CLOCK_REALTIME = 0
    mov rsi, rsp            ; timespec*
    mov eax, SYS_CLOCK_GETTIME
    syscall
    mov rax, [rsp]          ; seconds
    add rsp, 16

    ; Convert timestamp to decimal string
    lea rdi, [rel numbuf]
    call itoa64
    ; Append timestamp to backup_path
    lea rdi, [rel backup_path]
    call strlen
    lea rdi, [rel backup_path]
    add rdi, rax
    lea rsi, [rel numbuf]
    call strcpy

    ; Read vault file
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, BUF_SIZE
    call read_file
    mov r15, rax            ; bytes read

    ; Write backup
    lea rdi, [rel backup_path]
    lea rsi, [rel vault_buf]
    mov edx, r15d
    mov ecx, 0o600
    call write_file

    lea rdi, [rel msg_backup_ok]
    call print_str
    lea rdi, [rel backup_path]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    xor edi, edi
    call exit

; ── vault totp <name> — generate TOTP code ───────────────────
do_totp:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]
    lea rdi, [rel entry_name]
    call strcpy

    mov edi, 3
    call parse_output_flags

    call open_vault

    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    test rax, rax
    jz err_not_found

    mov rsi, rax
    call decrypt_entry

    ; TOTP secret is in the dedicated totp field (base32 encoded)
    ; Fall back to notes field for old-format entries
    lea rdi, [rel entry_totp]
    cmp byte [rdi], 0
    jne .totp_has_secret
    ; Try notes field as fallback (old format)
    lea rdi, [rel entry_notes]
    cmp byte [rdi], 0
    je .totp_no_secret
.totp_has_secret:

    ; Decode base32 secret (rdi already points to the right field)
    lea rsi, [rel totp_secret]
    call base32_decode       ; rax = decoded length
    test eax, eax
    jz .totp_no_secret

    mov r15d, eax           ; secret length

    ; Get current time
    sub rsp, 16
    xor edi, edi            ; CLOCK_REALTIME
    mov rsi, rsp
    mov eax, SYS_CLOCK_GETTIME
    syscall
    mov rax, [rsp]          ; seconds since epoch
    add rsp, 16

    ; Counter = time / 30 (TOTP time step)
    xor edx, edx
    mov rcx, 30
    div rcx                 ; rax = counter

    ; Store counter as 8-byte big-endian
    bswap rax
    mov [rel totp_counter], rax

    ; HMAC-SHA1(secret, counter)
    lea rdi, [rel totp_secret]
    mov esi, r15d
    lea rdx, [rel totp_counter]
    mov ecx, 8
    lea r8, [rel totp_hmac_out]
    call hmac_sha1

    ; Dynamic truncation (RFC 4226)
    lea rsi, [rel totp_hmac_out]
    movzx eax, byte [rsi + 19]
    and eax, 0x0f           ; offset
    movzx ecx, byte [rsi + rax]
    and ecx, 0x7f           ; strip high bit
    shl ecx, 8
    movzx edx, byte [rsi + rax + 1]
    or ecx, edx
    shl ecx, 8
    movzx edx, byte [rsi + rax + 2]
    or ecx, edx
    shl ecx, 8
    movzx edx, byte [rsi + rax + 3]
    or ecx, edx

    ; code = truncated_value % 1000000
    mov eax, ecx
    xor edx, edx
    mov ecx, 1000000
    div ecx
    ; edx = 6-digit code

    ; Print with leading zeros (always 6 digits)
    mov eax, edx
    lea rdi, [rel numbuf]
    call itoa_padded6

    cmp byte [rel output_json], 0
    je .totp_check_raw
    mov al, '{'
    call print_char
    lea rdi, [rel json_key_code]
    call print_json_quoted
    mov al, ':'
    call print_char
    lea rdi, [rel numbuf]
    call print_json_quoted
    mov al, '}'
    call print_char
    lea rdi, [rel msg_newline]
    call print_str
    jmp .totp_done

.totp_check_raw:
    cmp byte [rel output_raw], 0
    jne .totp_raw
    lea rdi, [rel msg_totp_code]
    call print_str
.totp_raw:
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

.totp_done:
    call zero_sensitive
    xor edi, edi
    call exit

.totp_no_secret:
    call zero_sensitive
    lea rdi, [rel err_msg_no_totp]
    lea rsi, [rel err_code_no_totp]
    lea rdx, [rel msg_totp_none]
    mov ecx, 1
    call emit_err

; ════════════════════════════════════════════════════════════════
; L4 Commands
; ════════════════════════════════════════════════════════════════

; ── vault wipe — securely destroy the vault ──────────────────
do_wipe:
    lea rdi, [rel vault_path]
    call file_exists
    test eax, eax
    jz err_no_vault

    ; Require confirmation
    lea rdi, [rel msg_wipe_confirm]
    call print_str
    lea rsi, [rel wipe_input]
    mov edx, 31
    call read_line_noprompt

    ; Compare with "DESTROY"
    lea rdi, [rel wipe_input]
    lea rsi, [rel wipe_confirm]
    call strcmp
    test eax, eax
    jnz .wipe_abort

    ; Overwrite vault file with random data 3 times
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, BUF_SIZE
    call read_file
    mov r15, rax            ; file size

    ; Pass 1: overwrite with zeros
    lea rdi, [rel vault_buf]
    mov ecx, r15d
    xor al, al
    rep stosb
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, r15d
    mov ecx, 0o600
    call write_file

    ; Pass 2: overwrite with 0xFF
    lea rdi, [rel vault_buf]
    mov ecx, r15d
    mov al, 0xFF
    rep stosb
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, r15d
    mov ecx, 0o600
    call write_file

    ; Pass 3: overwrite with random
    lea rdi, [rel vault_buf]
    mov esi, r15d
    call get_random
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, r15d
    mov ecx, 0o600
    call write_file

    ; Delete file
    lea rdi, [rel vault_path]
    mov eax, SYS_UNLINK
    syscall

    lea rdi, [rel msg_wipe_ok]
    call print_str
    xor edi, edi
    call exit

.wipe_abort:
    lea rdi, [rel msg_wipe_abort]
    call print_str
    xor edi, edi
    call exit

; ── vault unlock — stash derived key in Linux kernel keyring ─
; Pre-hardening: the key was written to /tmp/.vault-session-<uid> in plaintext.
; Now: add_key(2) places the 32-byte key in the user session keyring under
; description "vault:session". keyctl_set_timeout(SESSION_TIMEOUT) caps the
; window. The on-disk stub only holds the keyring serial — useless to any
; reader who can't also issue keyctl_read against the same uid.
do_unlock:
    call open_vault
    call build_session_path

    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem

    ; add_key("user", "vault:session:<hmac8>", derived_key, 32, SESSION_KEYRING)
    ; Description is per-vault so concurrent --vault-path vaults don't collide.
    ; Linux x86-64 syscall ABI: arg4 → r10, NOT rcx (rcx is clobbered by syscall).
    call build_keyring_desc
    lea rdi, [rel key_type_user]
    lea rsi, [rel keyring_desc]
    lea rdx, [rel derived_key]
    mov r10, 32
    mov r8, KEY_SPEC_SESSION_KEYRING
    mov eax, SYS_ADD_KEY
    syscall
    test rax, rax
    js .unlock_keyring_fail        ; negative errno → keyring unavailable

    ; Save the serial for the stub
    mov [rel session_buf + SESSION_SERIAL_OFFSET], eax

    ; keyctl(KEYCTL_SET_TIMEOUT, serial, SESSION_TIMEOUT)
    mov edi, KEYCTL_SET_TIMEOUT
    mov esi, eax                   ; serial
    mov edx, SESSION_TIMEOUT
    mov eax, SYS_KEYCTL
    syscall
    ; Ignore timeout-set failure: worst case the key persists until the
    ; user logs out, which is the default keyring lifetime anyway.

    ; Build stub
    call get_now_seconds
    add rax, SESSION_TIMEOUT
    mov [rel session_buf + SESSION_EXPIRY_OFFSET], rax

    ; Session identifier: 16-byte salt (stable for the vault's lifetime).
    ; Earlier scheme used the 32-byte HMAC slot, which changed on every save
    ; and invalidated sessions after any write.
    lea rsi, [rel vault_buf + 10]
    lea rdi, [rel session_buf + SESSION_VAULT_HMAC_OFFSET]
    mov ecx, SALT_LEN
    rep movsb
    ; Zero the remaining bytes of the slot so the on-disk stub is deterministic.
    mov ecx, HMAC_LEN
    sub ecx, SALT_LEN
    xor al, al
    rep stosb

    mov al, [rel keyfile_active]
    mov [rel session_buf + SESSION_KEYFILE_FLAG_OFFSET], al
    test al, al
    jz .unlock_no_keyfile

    call load_keyfile_hash
    lea rsi, [rel keyfile_hash]
    lea rdi, [rel session_buf + SESSION_KEYFILE_HASH_OFFSET]
    mov ecx, KEY_LEN
    rep movsb

.unlock_no_keyfile:
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, SESSION_FILE_SIZE
    mov ecx, 0o600
    call write_file
    cmp eax, SESSION_FILE_SIZE
    jne .unlock_write_fail

    mov byte [rel session_active], 1
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem

    lea rdi, [rel msg_unlocked]
    call emit_ok_simple

.unlock_write_fail:
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem
    lea rdi, [rel err_msg_session_write]
    lea rsi, [rel err_code_session_write]
    lea rdx, [rel msg_session_write_fail]
    mov ecx, 1
    call emit_err

.unlock_keyring_fail:
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem
    lea rdi, [rel err_msg_keyring]
    lea rsi, [rel err_code_keyring]
    lea rdx, [rel msg_keyring_unavailable]
    mov ecx, 1
    call emit_err

; ── vault lock — clear session keyring entry + wipe stub ────
do_lock:
    ; Load vault file so build_session_path can derive the per-vault hex suffix.
    ; If the vault file is missing, no session to clear; treat as no-op success.
    call read_vault_file
    test rax, rax
    jz .lock_no_session
    mov [rel vault_file_size], rax
    call build_session_path
    lea rdi, [rel session_path]
    call file_exists
    test eax, eax
    jz .lock_no_session

    ; Read the stub to recover the keyring serial, then invalidate the key.
    ; If the stub is unreadable or wrong size we still wipe the file.
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, SESSION_FILE_SIZE
    call read_file
    cmp eax, SESSION_FILE_SIZE
    jne .lock_wipe_only
    mov esi, [rel session_buf + SESSION_SERIAL_OFFSET]
    test esi, esi
    jz .lock_wipe_only
    mov edi, KEYCTL_INVALIDATE
    mov eax, SYS_KEYCTL
    syscall
    ; Ignore failure — wipe stub anyway

.lock_wipe_only:
    call wipe_session_file

    lea rdi, [rel msg_locked]
    call emit_ok_simple

.lock_no_session:
    ; "no active session" is a success state for lock (idempotent), so emit ok.
    lea rdi, [rel msg_no_session]
    call emit_ok_simple

; ── vault status [--json] ─────────────────────────────────────
; Inspect vault metadata without prompting for the master password.
; Reports: path, exists, version (1=PBKDF2, 2=Argon2id, 0=missing),
; kdf, entry count, session_active.
do_status:
    mov edi, 2
    call parse_output_flags

    ; Reset stats — use r12-r15 to hold values across prints
    ; r12 = exists (0/1), r13 = version (0/1/2), r14 = entry count, r15 = session_active
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d

    ; Check vault file existence
    lea rdi, [rel vault_path]
    call file_exists
    test eax, eax
    jz .stat_no_vault
    mov r12d, 1

    ; Read first 66 bytes for magic, version, and entry count
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, 66
    call read_file
    cmp eax, 66
    jl .stat_no_vault          ; treat truncated as missing for metadata purposes

    ; Read version (word at offset 8)
    movzx eax, word [rel vault_buf + 8]
    mov r13d, eax

    ; Read entry count (dword at offset 62)
    mov eax, [rel vault_buf + 62]
    mov r14d, eax

.stat_no_vault:
    ; Check session
    call build_session_path
    lea rdi, [rel session_path]
    call file_exists
    test eax, eax
    jz .stat_no_session
    mov r15d, 1
.stat_no_session:

    cmp byte [rel output_json], 0
    jne .stat_json

    ; ── plain output ──
    lea rdi, [rel status_label_path]
    call print_str
    lea rdi, [rel vault_path]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel status_label_exists]
    call print_str
    test r12d, r12d
    jz .stat_plain_exists_no
    lea rdi, [rel status_yes]
    jmp .stat_plain_exists_done
.stat_plain_exists_no:
    lea rdi, [rel status_no]
.stat_plain_exists_done:
    call print_str

    lea rdi, [rel status_label_version]
    call print_str
    cmp r13d, 1
    je .stat_plain_v1
    cmp r13d, 2
    je .stat_plain_v2
    cmp r13d, 3
    je .stat_plain_v3
    lea rdi, [rel status_v0]
    jmp .stat_plain_v_done
.stat_plain_v1:
    lea rdi, [rel status_v1]
    jmp .stat_plain_v_done
.stat_plain_v2:
    lea rdi, [rel status_v2]
    jmp .stat_plain_v_done
.stat_plain_v3:
    lea rdi, [rel status_v3]
.stat_plain_v_done:
    call print_str

    lea rdi, [rel status_label_kdf]
    call print_str
    cmp r13d, 1
    je .stat_plain_kdf_p
    cmp r13d, 2
    je .stat_plain_kdf_a
    cmp r13d, 3
    je .stat_plain_kdf_a
    lea rdi, [rel status_kdf_unknown]
    jmp .stat_plain_kdf_done
.stat_plain_kdf_p:
    lea rdi, [rel status_kdf_pbkdf2]
    jmp .stat_plain_kdf_done
.stat_plain_kdf_a:
    lea rdi, [rel status_kdf_argon2]
.stat_plain_kdf_done:
    call print_str

    lea rdi, [rel status_label_entries]
    call print_str
    mov eax, r14d
    lea rdi, [rel status_numbuf]
    call itoa
    lea rdi, [rel status_numbuf]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    lea rdi, [rel status_label_session]
    call print_str
    test r15d, r15d
    jz .stat_plain_session_no
    lea rdi, [rel status_yes]
    jmp .stat_plain_session_done
.stat_plain_session_no:
    lea rdi, [rel status_no]
.stat_plain_session_done:
    call print_str

    xor edi, edi
    call exit

.stat_json:
    ; ── JSON output: single-line object ──
    mov al, '{'
    call print_char
    lea rdi, [rel json_status_path]
    call print_str
    lea rdi, [rel vault_path]
    call print_json_quoted_body    ; writes raw escaped body to stdout (no quotes)
    lea rdi, [rel json_status_exists]
    call print_str
    test r12d, r12d
    jnz .stat_json_exists_yes
    lea rdi, [rel json_false_word]
    jmp .stat_json_exists_done
.stat_json_exists_yes:
    lea rdi, [rel json_true_word]
.stat_json_exists_done:
    call print_str

    lea rdi, [rel json_status_version]
    call print_str
    mov eax, r13d
    lea rdi, [rel status_numbuf]
    call itoa
    lea rdi, [rel status_numbuf]
    call print_str

    lea rdi, [rel json_status_kdf]
    call print_str
    cmp r13d, 1
    je .stat_json_kdf_p
    cmp r13d, 2
    je .stat_json_kdf_a
    cmp r13d, 3
    je .stat_json_kdf_a
    lea rdi, [rel json_kdf_unknown_word]
    jmp .stat_json_kdf_done
.stat_json_kdf_p:
    lea rdi, [rel json_kdf_pbkdf2_word]
    jmp .stat_json_kdf_done
.stat_json_kdf_a:
    lea rdi, [rel json_kdf_argon2_word]
.stat_json_kdf_done:
    call print_str

    lea rdi, [rel json_status_entries]
    call print_str
    mov eax, r14d
    lea rdi, [rel status_numbuf]
    call itoa
    lea rdi, [rel status_numbuf]
    call print_str

    lea rdi, [rel json_status_session]
    call print_str
    test r15d, r15d
    jnz .stat_json_session_yes
    lea rdi, [rel json_false_close]
    jmp .stat_json_session_done
.stat_json_session_yes:
    lea rdi, [rel json_true_close]
.stat_json_session_done:
    call print_str

    xor edi, edi
    call exit

; print_json_quoted_body — write JSON-escaped chars (no surrounding quotes) to STDOUT
;   rdi = null-terminated string
print_json_quoted_body:
    push rbx
    mov rbx, rdi
.pjqb_loop:
    mov al, [rbx]
    test al, al
    jz .pjqb_done
    cmp al, '"'
    je .pjqb_q
    cmp al, 92
    je .pjqb_bs
    cmp al, 10
    je .pjqb_n
    cmp al, 13
    je .pjqb_r
    cmp al, 9
    je .pjqb_t
    cmp al, 0x20
    jl .pjqb_skip
    call print_char
    jmp .pjqb_next
.pjqb_q:
    mov al, 92
    call print_char
    mov al, '"'
    call print_char
    jmp .pjqb_next
.pjqb_bs:
    mov al, 92
    call print_char
    mov al, 92
    call print_char
    jmp .pjqb_next
.pjqb_n:
    mov al, 92
    call print_char
    mov al, 'n'
    call print_char
    jmp .pjqb_next
.pjqb_r:
    mov al, 92
    call print_char
    mov al, 'r'
    call print_char
    jmp .pjqb_next
.pjqb_t:
    mov al, 92
    call print_char
    mov al, 't'
    call print_char
    jmp .pjqb_next
.pjqb_skip:
.pjqb_next:
    inc rbx
    jmp .pjqb_loop
.pjqb_done:
    pop rbx
    ret

; ── vault hidden <subcmd> [args] — plausible deniability ─────
; Hidden vault is appended to the main vault file.
; Format at end of file:
;   [7 bytes]   marker: "NYXHIDE"
;   [16 bytes]  hidden salt
;   [32 bytes]  hidden HMAC
;   [4 bytes]   hidden entry count
;   [entries...] same format as main vault entries
; A different password derives a different key for this section.
; Without the hidden password, the hidden data looks like random padding.
; ── vault migrate — re-encrypt all entries with new format ────
do_migrate:
    ; Dispatch:
    ;   migrate --upgrade-kdf  → v1/PBKDF2 → v3/Argon2id
    ;   migrate --upgrade-aead → v1/v2/v3 → v4 (ChaCha20-Poly1305 AEAD)
    ;   migrate                → legacy per-entry re-encode (adds TOTP field)
    mov rax, [rel argc]
    cmp rax, 3
    jl .migrate_legacy
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel upgrade_kdf_flag]
    call strcmp
    test eax, eax
    je .do_upgrade_kdf
    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel upgrade_aead_flag]
    call strcmp
    test eax, eax
    je do_migrate_upgrade_aead
    jmp .migrate_legacy
.do_upgrade_kdf:
    jmp do_migrate_upgrade_kdf
.migrate_legacy:
    call open_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz .migrate_done

    mov r15d, eax           ; total entries
    xor r13d, r13d          ; migrated count

    ; We need to rebuild the vault: read all entries, re-pack with totp field, re-encrypt
    ; Strategy: export to temp buffer, clear vault, re-import each entry

    ; First, collect all entries into a temp list by decrypting each one
    ; We'll process one at a time: decrypt, remove old, re-add with new format

.migrate_loop:
    cmp r13d, r15d
    jge .migrate_done

    ; Always process the first entry (index 0) since we remove it after
    lea rsi, [rel vault_buf]
    add rsi, 66             ; first entry

    ; Save entry name
    mov eax, [rsi]          ; name_len
    add rsi, 4
    lea rdi, [rel entry_name]
    mov ecx, eax
    push rax
    rep movsb
    pop rax
    lea rdi, [rel entry_name]
    mov byte [rdi + rax], 0

    ; Decrypt entry (rsi now points past name, back up to entry start)
    lea rsi, [rel vault_buf]
    add rsi, 66
    call decrypt_entry

    ; Print progress
    push r13
    push r15
    lea rdi, [rel msg_migrating]
    call print_str
    lea rdi, [rel entry_name]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    pop r15
    pop r13

    ; Remove the first entry
    lea rsi, [rel vault_buf]
    add rsi, 66
    call get_entry_size
    mov rcx, rax

    lea rdi, [rel vault_buf]
    add rdi, 66             ; dst = start of entries
    lea rsi, [rel vault_buf]
    add rsi, 66
    add rsi, rcx            ; src = past removed entry
    lea rdx, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdx, rax
    sub rdx, rsi            ; bytes remaining
    push rcx
    mov rcx, rdx
    rep movsb
    pop rcx

    lea rdi, [rel vault_buf]
    dec dword [rdi + 62]
    mov rax, [rel vault_file_size]
    sub rax, rcx
    mov [rel vault_file_size], rax

    ; If entry_totp is empty (old format), it stays empty — that's correct
    ; Re-pack with new format (includes totp field)
    call pack_entry_data
    mov r14, rax

    ; Re-encrypt
    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save

    inc r13d
    jmp .migrate_loop

.migrate_done:
    call zero_sensitive
    lea rdi, [rel msg_migrate_ok]
    call print_str
    xor edi, edi
    call exit

; ── vault migrate --upgrade-kdf ──────────────────────────────
; Re-key a v1/v2 vault to v3: Argon2id KDF + authenticated full header.
; Strategy:
;   1. Open with old KDF → derived_key holds old key
;   2. Snapshot the ciphertext entry section to migrate_old_entries
;   3. Generate new salt, derive new Argon2id key into migrate_new_key
;   4. Reset header: version=v3, new salt, HMAC slot zero, entry_count=0
;   5. Walk old entries: temp-swap derived_key=old, decrypt each, swap to new,
;      append via append_entry_and_save (which recomputes v3 HMAC)
;   6. Done — vault is now v3
do_migrate_upgrade_kdf:
    call open_vault

    ; Refuse if already v3+
    movzx eax, word [rel vault_buf + 8]
    cmp eax, VAULT_VERSION_V3
    jl .muk_proceed
    lea rdi, [rel msg_migrate_already_v3]
    call print_str
    xor edi, edi
    call exit
.muk_proceed:

    ; Snapshot the entry section size
    mov rax, [rel vault_file_size]
    sub rax, 66
    cmp rax, 65536
    jbe .muk_size_ok
    lea rdi, [rel msg_migrate_too_big]
    call print_err
    mov edi, 1
    call exit
.muk_size_ok:
    mov [rel migrate_old_entries_size], rax

    ; Save old entry count and entries section
    mov eax, [rel vault_buf + 62]
    mov [rel migrate_old_entry_count], eax
    lea rsi, [rel vault_buf + 66]
    lea rdi, [rel migrate_old_entries]
    mov rcx, [rel migrate_old_entries_size]
    rep movsb

    ; Save old derived_key
    lea rsi, [rel derived_key]
    lea rdi, [rel migrate_old_key]
    mov ecx, 32
    rep movsb

    ; ── Build v3 header in vault_buf ──
    mov word [rel vault_buf + 8], VAULT_VERSION_V3

    ; New salt → vault_buf[10..26] and vault_salt
    lea rdi, [rel vault_buf + 10]
    mov esi, 16
    call get_random
    lea rsi, [rel vault_buf + 10]
    lea rdi, [rel vault_salt]
    mov ecx, 16
    rep movsb

    ; Keep iter field as-is (unused for v3, but preserve sane value)
    mov dword [rel vault_buf + 26], PBKDF2_ITER

    ; Zero HMAC slot + entry_count
    lea rdi, [rel vault_buf + 30]
    mov ecx, 32
    xor al, al
    rep stosb
    mov dword [rel vault_buf + 62], 0
    mov qword [rel vault_file_size], 66

    ; Derive new Argon2id key with new salt
    lea rdi, [rel master_pw]
    call strlen
    mov r12, rax
    lea rdi, [rel master_pw]
    mov rsi, r12
    lea rdx, [rel vault_salt]
    mov ecx, 16
    lea r8, [rel derived_key]
    call argon2id_hash

    ; Apply keyfile XOR if active (mirrors open_vault behavior)
    cmp byte [rel keyfile_active], 0
    je .muk_no_keyfile
    call apply_keyfile
.muk_no_keyfile:

    ; Save the new derived key for swap during the re-encrypt loop
    lea rsi, [rel derived_key]
    lea rdi, [rel migrate_new_key]
    mov ecx, 32
    rep movsb

    ; ── Walk old entries: decrypt with old key, append with new key ──
    ; Cursor goes in memory (migrate_cursor) because the helpers we call
    ; (append_entry_and_save in particular) overwrite r13/r14 as scratch.
    mov eax, [rel migrate_old_entry_count]
    mov [rel migrate_remaining], eax
    lea rax, [rel migrate_old_entries]
    mov [rel migrate_cursor], rax

.muk_walk:
    mov eax, [rel migrate_remaining]
    test eax, eax
    jz .muk_walk_done

    ; Swap derived_key ← migrate_old_key, then decrypt this entry
    lea rsi, [rel migrate_old_key]
    lea rdi, [rel derived_key]
    mov ecx, 32
    rep movsb

    ; Decrypt entry at migrate_cursor → fills entry_user/pass/url/notes/totp
    mov rsi, [rel migrate_cursor]
    call decrypt_entry

    ; Set entry_name from cursor (decrypt_entry doesn't touch entry_name)
    mov rsi, [rel migrate_cursor]
    mov eax, [rsi]              ; name_len
    add rsi, 4
    mov edx, eax                ; preserve length for terminator
    lea rdi, [rel entry_name]
    mov ecx, eax
    rep movsb
    mov byte [rdi + rdx], 0     ; null terminator

    ; Advance cursor past this entry: 4 + name_len + 4 + IV(16) + enc_data_len
    mov rax, [rel migrate_cursor]
    mov ecx, [rax]              ; name_len
    add rax, 4
    add rax, rcx                ; past name
    mov ecx, [rax]              ; enc_data_len
    add rax, 4                  ; past enc_data_len field
    add rax, IV_LEN             ; past IV
    add rax, rcx                ; past ciphertext
    mov [rel migrate_cursor], rax

    ; Swap derived_key ← migrate_new_key for re-encrypt
    lea rsi, [rel migrate_new_key]
    lea rdi, [rel derived_key]
    mov ecx, 32
    rep movsb

    ; Re-pack and re-encrypt (mirrors do_add's append path)
    call pack_entry_data
    ; pack_entry_data returns plaintext length in rax. append_entry_and_save
    ; reads r14d as the ciphertext length (same value since CTR mode), so:
    mov r14d, eax

    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel derived_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov ecx, r14d
    lea r8, [rel crypt_buf]
    call ctr_crypt

    call append_entry_and_save

    dec dword [rel migrate_remaining]
    jmp .muk_walk

.muk_walk_done:
    ; Wipe scratch
    lea rdi, [rel migrate_old_key]
    mov ecx, 32
    xor al, al
    rep stosb
    lea rdi, [rel migrate_new_key]
    mov ecx, 32
    xor al, al
    rep stosb
    lea rdi, [rel migrate_old_entries]
    mov rcx, [rel migrate_old_entries_size]
    xor al, al
    rep stosb

    call zero_sensitive

    lea rdi, [rel msg_migrate_upgrade_ok]
    call print_str
    xor edi, edi
    call exit

; ════════════════════════════════════════════════════════════════
; vault migrate --upgrade-aead — convert v1/v2/v3 vault to v4
; (ChaCha20-Poly1305 AEAD). Each entry's per-entry CTR ciphertext is
; decrypted in place to plaintext (entry layout unchanged), then the
; whole body is re-sealed under AEAD on save.
;
; Refuses to migrate if a hidden section exists (hidden vaults are not
; yet supported under v4).
; ════════════════════════════════════════════════════════════════
do_migrate_upgrade_aead:
    call open_vault

    ; Refuse if already v4.
    movzx eax, word [rel vault_buf + 8]
    cmp eax, VAULT_VERSION_V4
    jne .ua_not_v4
    lea rdi, [rel msg_already_v4]
    call print_str
    xor edi, edi
    call exit
.ua_not_v4:

    ; Refuse if a hidden section is detected. Hidden sections in v3 live
    ; after the main entries, marked by a specific magic. Conservative
    ; check: if vault_file_size > 62 + walk_size_of_main_entries, bail.
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15d, [rel vault_buf + 62]      ; entry count
    lea rbx, [rel vault_buf + 66]       ; cursor
    mov r12, 4                          ; main body bytes so far (entry_count)
    xor r13, r13                        ; loop counter

.ua_walk_main:
    cmp r13d, r15d
    jge .ua_walk_done
    mov eax, [rbx]                      ; name_len
    lea rcx, [rbx + 4]
    add rcx, rax                        ; → enc_len field
    mov edx, [rcx]                      ; enc_data_len
    add rcx, 4
    add rcx, IV_LEN
    add rcx, rdx                        ; → next entry
    sub rcx, rbx                        ; entry size
    add r12, rcx
    add rbx, rcx
    inc r13
    jmp .ua_walk_main
.ua_walk_done:

    mov rax, [rel vault_file_size]
    sub rax, 62
    cmp rax, r12
    je .ua_no_hidden
    lea rdi, [rel msg_hidden_v4_unsupported]
    call print_str
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov edi, 1
    call exit
.ua_no_hidden:

    ; ── In-place CTR-decrypt each entry's data slot ────────
    mov r15d, [rel vault_buf + 62]
    lea rbx, [rel vault_buf + 66]
    xor r13, r13

.ua_decrypt_loop:
    cmp r13d, r15d
    jge .ua_decrypt_done
    mov eax, [rbx]                      ; name_len
    lea r14, [rbx + 4]
    add r14, rax                        ; → enc_len field
    mov r12d, [r14]                     ; ct_len
    add r14, 4                          ; → IV
    mov rcx, r14                        ; iv ptr
    add r14, IV_LEN                     ; → ct
    ; ctr_crypt_raw(key=derived_key, iv=rcx, in=r14, len=r12, out=r14)
    lea rdi, [rel derived_key]
    mov rsi, rcx
    mov rdx, r14
    mov ecx, r12d
    mov r8, r14
    push rax
    push r13
    push r14
    push r15
    call ctr_crypt_raw
    pop r15
    pop r14
    pop r13
    pop rax
    ; Advance rbx past this entry: 4 + name_len + 4 + 16 + ct_len
    add rbx, 4
    add rbx, rax
    add rbx, 4
    add rbx, 16
    add rbx, r12
    inc r13
    jmp .ua_decrypt_loop
.ua_decrypt_done:

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    ; Switch version to V4 and seal
    mov word [rel vault_buf + 8], VAULT_VERSION_V4
    mov word [rel g_vault_version], VAULT_VERSION_V4

    call recalc_and_save

    call zero_sensitive

    lea rdi, [rel msg_migrate_upgrade_aead_ok]
    call print_str
    xor edi, edi
    call exit

do_hidden:
    ; Hidden vault operations are not supported on v4 vaults. The main-body
    ; AEAD covers the entire body, but the hidden section has its own
    ; password and key — that pairing has not been wired through the v4
    ; AEAD path yet. Peek the on-disk version and refuse if v4.
    call read_vault_file
    test rax, rax
    jz .hidden_no_v4_block
    cmp rax, 10
    jl .hidden_no_v4_block
    movzx eax, word [rel vault_buf + 8]
    cmp ax, VAULT_VERSION_V4
    jne .hidden_no_v4_block
    lea rdi, [rel msg_hidden_v4_blocked]
    call print_str
    mov edi, 1
    call exit
.hidden_no_v4_block:

    mov rax, [rel argc]
    cmp rax, 3
    jl .hidden_usage

    ; Get sub-command
    mov rax, [rel argv]
    mov rdi, [rax+16]       ; argv[2]

    lea rsi, [rel hid_init_str]
    call strcmp
    test eax, eax
    jz do_hidden_init

    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel hid_add_str]
    call strcmp
    test eax, eax
    jz do_hidden_add

    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel hid_get_str]
    call strcmp
    test eax, eax
    jz do_hidden_get

    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel hid_list_str]
    call strcmp
    test eax, eax
    jz do_hidden_list

    mov rax, [rel argv]
    mov rdi, [rax+16]
    lea rsi, [rel hid_rm_str]
    call strcmp
    test eax, eax
    jz do_hidden_rm

.hidden_usage:
    lea rdi, [rel msg_hidden_usage]
    call print_str
    xor edi, edi
    call exit

; ── vault hidden init — initialize hidden vault ──────────────
do_hidden_init:
    ; First verify the main vault (need main password)
    call open_vault

    ; Read hidden password
    lea rdi, [rel msg_hidden_pw]
    lea rsi, [rel hidden_pw]
    mov edx, 255
    call read_password

    lea rdi, [rel prompt_confirm]
    lea rsi, [rel hidden_pw2]
    mov edx, 255
    call read_password

    ; Compare
    lea rdi, [rel hidden_pw]
    call strlen
    mov r15, rax
    lea rdi, [rel hidden_pw]
    lea rsi, [rel hidden_pw2]
    mov ecx, eax
    call memcmp
    test eax, eax
    jnz .hidden_mismatch

    ; Generate hidden salt
    lea rdi, [rel hidden_salt]
    mov esi, 16
    call get_random

    ; Derive hidden key
    lea rdi, [rel hidden_pw]
    mov rsi, r15
    lea rdx, [rel hidden_salt]
    mov ecx, 16
    mov r8, PBKDF2_ITER
    lea r9, [rel hidden_key]
    call pbkdf2_sha256

    ; Build hidden section: marker + salt + hmac + entry_count(0)
    ; Append to end of main vault file
    mov rax, [rel vault_file_size]
    lea rdi, [rel vault_buf]
    add rdi, rax             ; end of current data

    ; Marker (7 bytes)
    lea rsi, [rel hidden_marker]
    mov ecx, 7
    rep movsb

    ; Salt (16 bytes)
    lea rsi, [rel hidden_salt]
    mov ecx, 16
    rep movsb

    ; HMAC placeholder (32 bytes)
    push rdi                 ; save HMAC position
    mov ecx, 32
    xor al, al
    rep stosb

    ; Entry count (4 bytes)
    mov dword [rdi], 0
    add rdi, 4

    ; Calculate new file size
    lea rax, [rel vault_buf]
    sub rdi, rax
    mov [rel vault_file_size], rdi

    ; Compute hidden HMAC over data after hidden HMAC field
    pop r14                  ; HMAC position in vault_buf
    lea rdi, [rel hidden_key]
    mov rsi, 32
    lea rdx, [r14 + 32]     ; data starts after HMAC field = entry count
    mov rcx, 4               ; entry count (0 entries initially)
    lea r8, [rel hidden_hmac]
    call hmac_sha256

    ; Copy HMAC into buffer
    mov rdi, r14
    lea rsi, [rel hidden_hmac]
    mov ecx, 32
    rep movsb

    ; Recompute main vault HMAC (covers offset 62 to end, including hidden section)
    mov rax, [rel vault_file_size]
    sub rax, 62
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256

    ; Write main HMAC to offset 30
    lea rdi, [rel vault_buf]
    add rdi, 30
    lea rsi, [rel vault_hmac]
    mov ecx, 32
    rep movsb

    ; Write entire vault file
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    mov edx, eax
    mov ecx, 0o600
    call write_file

    ; Zero sensitive
    lea rdi, [rel hidden_pw]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel hidden_pw2]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel hidden_key]
    mov ecx, 32
    call zero_mem
    call zero_sensitive

    lea rdi, [rel msg_hidden_init]
    call print_str
    xor edi, edi
    call exit

.hidden_mismatch:
    lea rdi, [rel err_msg_pw_mismatch]
    lea rsi, [rel err_code_pw_mismatch]
    lea rdx, [rel msg_mismatch]
    mov ecx, 1
    call emit_err

; ── vault hidden list — list hidden entries ──────────────────
do_hidden_list:
    call open_vault
    call open_hidden_vault   ; derives hidden_key, finds hidden section

    ; Read entry count from hidden section
    mov rsi, [rel hidden_section_ptr]
    mov eax, [rsi]           ; entry count
    test eax, eax
    jz .hidden_list_empty

    mov ecx, eax
    add rsi, 4               ; first entry

.hidden_list_loop:
    test ecx, ecx
    jz .hidden_list_done
    push rcx
    push rsi

    mov eax, [rsi]           ; name_len
    add rsi, 4
    mov rdi, rsi
    push rax
    call print_n
    lea rdi, [rel msg_newline]
    call print_str
    pop rax

    pop rsi
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax

    pop rcx
    dec ecx
    jmp .hidden_list_loop

.hidden_list_empty:
    lea rdi, [rel msg_hidden_empty]
    call print_str
.hidden_list_done:
    call zero_sensitive
    xor edi, edi
    call exit

; ── vault hidden add <name> — add to hidden vault ────────────
do_hidden_add:
    mov rax, [rel argc]
    cmp rax, 4
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+24]        ; argv[3]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault
    call open_hidden_vault

    ; Read fields
    lea rdi, [rel prompt_username]
    lea rsi, [rel entry_user]
    mov edx, 255
    call read_line

    lea rdi, [rel prompt_password]
    lea rsi, [rel entry_pass]
    mov edx, 255
    call read_password

    lea rdi, [rel prompt_url]
    lea rsi, [rel entry_url]
    mov edx, 255
    call read_line

    lea rdi, [rel prompt_notes]
    lea rsi, [rel entry_notes]
    mov edx, 255
    call read_line

    lea rdi, [rel prompt_totp]
    lea rsi, [rel entry_totp]
    mov edx, 255
    call read_line

    ; Pack entry data
    call pack_entry_data
    mov r14, rax

    ; Generate IV and encrypt with HIDDEN key
    lea rdi, [rel iv_buf]
    mov esi, IV_LEN
    call get_random

    lea rdi, [rel hidden_key]
    lea rsi, [rel iv_buf]
    lea rdx, [rel entry_data]
    mov rcx, r14
    lea r8, [rel crypt_buf]
    call ctr_crypt_raw              ; hidden vault keeps legacy CTR

    ; Append entry to hidden section
    call append_hidden_entry_and_save

    call zero_sensitive
    lea rdi, [rel hidden_key]
    mov ecx, 32
    call zero_mem

    lea rdi, [rel msg_hidden_add]
    call print_str
    xor edi, edi
    call exit

; ── vault hidden get <name> — get from hidden vault ──────────
do_hidden_get:
    mov rax, [rel argc]
    cmp rax, 4
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+24]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault
    call open_hidden_vault

    ; Find entry in hidden section
    lea rdi, [rel entry_name]
    call find_hidden_entry
    test rax, rax
    jz err_not_found

    ; Decrypt with hidden key
    mov rsi, rax
    call decrypt_hidden_entry

    ; Print all fields
    lea rdi, [rel label_name]
    call print_str
    lea rdi, [rel entry_name]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    lea rdi, [rel label_user]
    call print_str
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    lea rdi, [rel label_pass]
    call print_str
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    lea rdi, [rel label_url]
    call print_str
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    lea rdi, [rel label_notes]
    call print_str
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    cmp byte [rel entry_totp], 0
    jz .hidden_get_done
    lea rdi, [rel label_totp2]
    call print_str
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

.hidden_get_done:
    call zero_sensitive
    lea rdi, [rel hidden_key]
    mov ecx, 32
    call zero_mem
    xor edi, edi
    call exit

; ── vault hidden rm <name> — remove from hidden vault ────────
do_hidden_rm:
    mov rax, [rel argc]
    cmp rax, 4
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+24]
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault
    call open_hidden_vault

    lea rdi, [rel entry_name]
    call find_hidden_entry
    test rax, rax
    jz err_not_found

    ; Remove entry: calculate size, shift data, decrement count
    mov rsi, rax
    call get_entry_size
    mov rcx, rax             ; entry size

    mov rdi, rsi
    lea r8, [rsi + rcx]     ; past this entry
    ; Find end of hidden data
    mov rax, [rel vault_file_size]
    lea rdx, [rel vault_buf]
    add rdx, rax
    sub rdx, r8
    push rcx
    mov rcx, rdx
    mov rsi, r8
    rep movsb
    pop rcx

    ; Decrement hidden entry count
    mov rdi, [rel hidden_section_ptr]
    dec dword [rdi]

    ; Decrease file size
    mov rax, [rel vault_file_size]
    sub rax, rcx
    mov [rel vault_file_size], rax

    ; Recompute hidden HMAC and main HMAC, save
    call recalc_hidden_and_save

    call zero_sensitive
    lea rdi, [rel hidden_key]
    mov ecx, 32
    call zero_mem
    lea rdi, [rel msg_removed]
    call print_str
    xor edi, edi
    call exit

; ════════════════════════════════════════════════════════════════
; L4 Helpers
; ════════════════════════════════════════════════════════════════

; build_session_path — construct /tmp/.vault-session-<uid>
build_session_path:
    push rbx
    push r12
    lea rdi, [rel session_path]
    lea rsi, [rel session_path_prefix]
    call strcpy
    lea rdi, [rel session_path]
    call strlen
    lea rdi, [rel session_path]
    add rdi, rax
    ; Get UID
    mov eax, SYS_GETUID
    syscall
    push rdi
    lea rdi, [rel numbuf]
    call itoa
    pop rdi
    lea rsi, [rel numbuf]
    call strcpy
    ; Append "-<hex16>" derived from the 16-byte salt (stable across saves).
    ; Earlier scheme used the HMAC slot, which changed on every save and
    ; orphaned the session stub. Salt is generated at init and never rewritten.
    lea rdi, [rel session_path]
    call strlen
    lea rdi, [rel session_path]
    add rdi, rax
    mov byte [rdi], '-'
    inc rdi
    mov r12, rdi
    lea rbx, [rel vault_buf + 10]
    mov ecx, 8
.bsp_hex_loop:
    movzx eax, byte [rbx]
    mov edx, eax
    shr edx, 4
    and edx, 0x0F
    cmp edx, 10
    jl .bsp_hi_d
    add edx, 'a' - 10
    jmp .bsp_hi_done
.bsp_hi_d:
    add edx, '0'
.bsp_hi_done:
    mov [r12], dl
    inc r12
    mov edx, eax
    and edx, 0x0F
    cmp edx, 10
    jl .bsp_lo_d
    add edx, 'a' - 10
    jmp .bsp_lo_done
.bsp_lo_d:
    add edx, '0'
.bsp_lo_done:
    mov [r12], dl
    inc r12
    inc rbx
    dec ecx
    jnz .bsp_hex_loop
    mov byte [r12], 0
    pop r12
    pop rbx
    ret

; build_keyring_desc — fill keyring_desc with "vault:session:<hex>" where
; hex is the first 8 bytes of the vault_hmac slot in the file header,
; lower-case hex. This makes the keyring slot unique per vault file so
; multiple --vault-path vaults don't collide.
build_keyring_desc:
    push rbx
    push r12
    ; Copy prefix
    lea rsi, [rel key_desc_prefix]
    lea rdi, [rel keyring_desc]
    call strcpy
    ; Find end of prefix
    lea rdi, [rel keyring_desc]
    call strlen
    lea r12, [rel keyring_desc]
    add r12, rax
    ; Emit 16 hex chars from the first 8 bytes of the salt (stable across saves)
    lea rbx, [rel vault_buf + 10]
    mov ecx, 8
.bkd_loop:
    movzx eax, byte [rbx]
    mov edx, eax
    shr edx, 4
    and edx, 0x0F
    cmp edx, 10
    jl .bkd_hi_dig
    add edx, 'a' - 10
    jmp .bkd_hi_done
.bkd_hi_dig:
    add edx, '0'
.bkd_hi_done:
    mov [r12], dl
    inc r12
    mov edx, eax
    and edx, 0x0F
    cmp edx, 10
    jl .bkd_lo_dig
    add edx, 'a' - 10
    jmp .bkd_lo_done
.bkd_lo_dig:
    add edx, '0'
.bkd_lo_done:
    mov [r12], dl
    inc r12
    inc rbx
    dec ecx
    jnz .bkd_loop
    mov byte [r12], 0
    pop r12
    pop rbx
    ret

; get_now_seconds — current CLOCK_REALTIME seconds
get_now_seconds:
    sub rsp, 16
    xor edi, edi
    mov rsi, rsp
    mov eax, SYS_CLOCK_GETTIME
    syscall
    mov rax, [rsp]
    add rsp, 16
    ret

; wipe_session_file — securely wipe and delete session file
wipe_session_file:
    ; Overwrite with zeros
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, SESSION_FILE_SIZE
    mov ecx, 0o600
    call write_file
    ; Delete
    lea rdi, [rel session_path]
    mov eax, SYS_UNLINK
    syscall
    mov byte [rel session_active], 0
    ret

; try_load_session — check for session file and load cached key
;   Returns: eax = 1 if session loaded (derived_key set), 0 if not
try_load_session:
    push rcx
    push rsi
    push rdi

    mov byte [rel session_active], 0
    call build_session_path

    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, 128
    call read_file
    cmp eax, SESSION_FILE_SIZE
    jne .tls_invalid

    call get_now_seconds
    cmp rax, [rel session_buf + SESSION_EXPIRY_OFFSET]
    ja .tls_invalid

    ; Match by 16-byte salt (stable across saves). The remaining bytes of
    ; the SESSION_VAULT_HMAC slot are written as zero on unlock; we only
    ; compare the meaningful prefix.
    lea rdi, [rel session_buf + SESSION_VAULT_HMAC_OFFSET]
    lea rsi, [rel vault_buf + 10]
    mov ecx, SALT_LEN
    call ct_memcmp
    test eax, eax
    jnz .tls_invalid

    mov al, [rel session_buf + SESSION_KEYFILE_FLAG_OFFSET]
    cmp al, [rel keyfile_active]
    jne .tls_invalid
    test al, al
    jz .tls_load_key

    call load_keyfile_hash
    lea rdi, [rel session_buf + SESSION_KEYFILE_HASH_OFFSET]
    lea rsi, [rel keyfile_hash]
    mov ecx, KEY_LEN
    call ct_memcmp
    test eax, eax
    jnz .tls_invalid

.tls_load_key:
    ; Fetch derived_key from the kernel keyring by serial.
    ; keyctl(KEYCTL_READ, serial, derived_key, 32) → returns 32 on success
    ; (or larger if the key is longer; in practice always 32 here).
    mov esi, [rel session_buf + SESSION_SERIAL_OFFSET]
    test esi, esi
    jz .tls_invalid
    mov edi, KEYCTL_READ
    lea rdx, [rel derived_key]
    mov r10d, 32
    mov eax, SYS_KEYCTL
    syscall
    cmp eax, 32
    jne .tls_invalid               ; expired key, wrong uid, etc.

    mov byte [rel session_active], 1
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem
    mov eax, 1
    jmp .tls_done

.tls_invalid:
    lea rdi, [rel session_path]
    call file_exists
    test eax, eax
    jz .tls_no_file
    call wipe_session_file
.tls_no_file:
    lea rdi, [rel session_buf]
    mov ecx, 128
    call zero_mem
    xor eax, eax

.tls_done:
    pop rdi
    pop rsi
    pop rcx
    ret

; open_hidden_vault — prompt for hidden password, find hidden section
;   Requires: vault already loaded via open_vault
;   Sets: hidden_key, hidden_section_ptr
open_hidden_vault:
    push r12
    push r15

    ; Read hidden password
    lea rdi, [rel msg_hidden_pw]
    lea rsi, [rel hidden_pw]
    mov edx, 255
    call read_password
    lea rdi, [rel hidden_pw]
    call strlen
    mov r15, rax

    ; Find hidden marker in vault_buf
    lea rdi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdi, rax
    ; Search backwards for NYXHIDE marker
    sub rdi, 7               ; minimum offset for marker
.ohv_scan:
    lea rsi, [rel vault_buf]
    add rsi, 66              ; don't search in header
    cmp rdi, rsi
    jl .ohv_no_hidden

    lea rsi, [rel hidden_marker]
    push rdi
    mov ecx, 7
    call memcmp
    pop rdi
    test eax, eax
    jz .ohv_found
    dec rdi
    jmp .ohv_scan

.ohv_found:
    ; rdi points to NYXHIDE marker
    add rdi, 7               ; skip marker

    ; Read hidden salt (16 bytes)
    lea rsi, [rel hidden_salt]
    push rdi
    mov ecx, 16
.ohv_copy_salt:
    mov al, [rdi]
    mov [rsi], al
    inc rdi
    inc rsi
    dec ecx
    jnz .ohv_copy_salt
    pop rdi
    add rdi, 16

    ; Derive hidden key
    push rdi
    lea rdi, [rel hidden_pw]
    mov rsi, r15
    lea rdx, [rel hidden_salt]
    mov ecx, 16
    mov r8, PBKDF2_ITER
    lea r9, [rel hidden_key]
    call pbkdf2_sha256
    pop rdi

    ; Skip stored HMAC (32 bytes) — we'll verify later
    add rdi, 32

    ; rdi now points to hidden entry count
    mov [rel hidden_section_ptr], rdi

    ; Verify hidden HMAC
    mov rdi, [rel hidden_section_ptr]
    ; Calculate hidden data length: from entry count to end of file
    lea rax, [rel vault_buf]
    mov rcx, [rel vault_file_size]
    add rax, rcx             ; end of file
    sub rax, rdi             ; hidden data length
    mov rcx, rax

    lea rdi, [rel hidden_key]
    mov rsi, 32
    mov rdx, [rel hidden_section_ptr]
    ; rcx already set
    lea r8, [rel hidden_hmac]
    call hmac_sha256

    ; Compare with stored HMAC — constant-time to deny timing side-channels.
    lea rdi, [rel hidden_hmac]
    mov rsi, [rel hidden_section_ptr]
    sub rsi, 32
    mov ecx, 32
    call ct_memcmp
    test eax, eax
    jnz .ohv_hmac_fail

    ; Zero hidden password
    lea rdi, [rel hidden_pw]
    mov ecx, 256
    call zero_mem

    pop r15
    pop r12
    ret

.ohv_no_hidden:
    lea rdi, [rel err_msg_no_vault]
    lea rsi, [rel err_code_no_vault]
    lea rdx, [rel msg_no_vault]
    mov ecx, 1
    call emit_err

.ohv_hmac_fail:
    lea rdi, [rel err_msg_auth_failed]
    lea rsi, [rel err_code_auth_failed]
    lea rdx, [rel msg_hmac_fail]
    mov ecx, 1
    call emit_err

; find_hidden_entry — find entry by name in hidden section
;   rdi = name (null-terminated)
;   Returns: rax = pointer to entry, 0 if not found
find_hidden_entry:
    push rbx
    push rcx
    push rdx
    push rsi
    push r12

    mov r12, rdi
    mov rsi, [rel hidden_section_ptr]
    mov eax, [rsi]
    test eax, eax
    jz .fhe_notfound

    mov ecx, eax
    add rsi, 4

.fhe_loop:
    test ecx, ecx
    jz .fhe_notfound
    push rcx
    push rsi

    mov eax, [rsi]
    mov r13d, eax
    add rsi, 4

    mov rdi, r12
    call strlen
    cmp eax, r13d
    jne .fhe_next

    mov rdi, r12
    mov ecx, r13d
    call memcmp
    test eax, eax
    jnz .fhe_next

    pop rax
    pop rcx
    jmp .fhe_done

.fhe_next:
    pop rsi
    mov eax, [rsi]
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax
    pop rcx
    dec ecx
    jmp .fhe_loop

.fhe_notfound:
    xor eax, eax
.fhe_done:
    pop r12
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; decrypt_hidden_entry — decrypt entry using hidden_key
;   rsi = pointer to entry in vault_buf
decrypt_hidden_entry:
    push rbx
    push r12

    ; Skip name
    mov eax, [rsi]
    add rsi, 4
    add rsi, rax

    ; Encrypted data length
    mov r12d, [rsi]
    add rsi, 4

    ; IV
    mov rdi, rsi
    add rsi, IV_LEN

    ; Decrypt with hidden_key
    push rsi
    mov rsi, rdi
    lea rdi, [rel hidden_key]
    pop rdx
    mov ecx, r12d
    lea r8, [rel entry_data]
    call ctr_crypt_raw              ; hidden vault keeps legacy CTR

    ; Parse fields
    lea rsi, [rel entry_data]
    lea rdi, [rel entry_user]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_pass]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_url]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_notes]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    ; TOTP (bounds check like decrypt_entry)
    lea rdi, [rel entry_data]
    add rdi, r12
    cmp rsi, rdi
    jge .dhe_no_totp
    lea rdi, [rel entry_totp]
    call strcpy
    jmp .dhe_done
.dhe_no_totp:
    mov byte [rel entry_totp], 0
.dhe_done:

    pop r12
    pop rbx
    ret

; append_hidden_entry_and_save — append entry to hidden section
append_hidden_entry_and_save:
    push rbx
    push r12

    ; Find end of file
    lea rdi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdi, rax

    ; Append entry (same format as main vault)
    lea rsi, [rel entry_name]
    push rdi
    mov rdi, rsi
    call strlen
    pop rdi
    mov [rdi], eax
    mov r12d, eax
    add rdi, 4

    lea rsi, [rel entry_name]
    mov ecx, r12d
    rep movsb

    mov eax, r14d
    mov [rdi], eax
    add rdi, 4

    lea rsi, [rel iv_buf]
    mov ecx, IV_LEN
    rep movsb

    lea rsi, [rel crypt_buf]
    mov ecx, r14d
    rep movsb

    ; Update file size
    lea rax, [rel vault_buf]
    sub rdi, rax
    mov [rel vault_file_size], rdi

    ; Increment hidden entry count
    mov rdi, [rel hidden_section_ptr]
    inc dword [rdi]

    ; Recompute and save
    call recalc_hidden_and_save

    pop r12
    pop rbx
    ret

; recalc_hidden_and_save — recompute hidden HMAC and main HMAC, write file
recalc_hidden_and_save:
    push rbx

    ; Recalculate file size from hidden entries
    mov rsi, [rel hidden_section_ptr]
    mov eax, [rsi]
    mov ecx, eax
    add rsi, 4
.rhs_loop:
    test ecx, ecx
    jz .rhs_done
    mov eax, [rsi]
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax
    dec ecx
    jmp .rhs_loop
.rhs_done:
    ; rsi now points past last hidden entry = end of file
    lea rax, [rel vault_buf]
    sub rsi, rax
    mov [rel vault_file_size], rsi

    ; Compute hidden HMAC over hidden data (from entry count to end)
    mov rdi, [rel hidden_section_ptr]
    lea rax, [rel vault_buf]
    mov rcx, [rel vault_file_size]
    add rax, rcx
    sub rax, rdi             ; hidden data length
    mov rcx, rax

    push rcx
    lea rdi, [rel hidden_key]
    mov rsi, 32
    mov rdx, [rel hidden_section_ptr]
    ; rcx already set
    lea r8, [rel hidden_hmac]
    call hmac_sha256
    pop rcx

    ; Write hidden HMAC to vault_buf (32 bytes before entry count)
    mov rdi, [rel hidden_section_ptr]
    sub rdi, 32
    lea rsi, [rel hidden_hmac]
    mov ecx, 32
    rep movsb

    ; Recompute main HMAC (offset 62 to end, includes hidden section)
    mov rax, [rel vault_file_size]
    sub rax, 62
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256

    ; Write main HMAC to offset 30
    lea rdi, [rel vault_buf]
    add rdi, 30
    lea rsi, [rel vault_hmac]
    mov ecx, 32
    rep movsb

    ; Write file
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    mov edx, eax
    mov ecx, 0o600
    call write_file

    pop rbx
    ret

; apply_keyfile — read keyfile, hash it, XOR with derived_key
apply_keyfile:
    push rbx
    push rcx

    call load_keyfile_hash

    ; XOR derived_key with keyfile_hash
    lea rdi, [rel derived_key]
    lea rsi, [rel keyfile_hash]
    mov ecx, 32
.akf_xor:
    mov al, [rsi]
    xor [rdi], al
    inc rdi
    inc rsi
    dec ecx
    jnz .akf_xor

.akf_done:
    pop rcx
    pop rbx
    ret

; load_keyfile_hash — read keyfile and hash it into keyfile_hash
load_keyfile_hash:
    mov rdi, [rel keyfile_path]
    lea rsi, [rel keyfile_buf]
    mov edx, 256
    call read_file
    test eax, eax
    jnz .lkh_loaded
    lea rdi, [rel err_msg_keyfile]
    lea rsi, [rel err_code_keyfile]
    lea rdx, [rel msg_keyfile_required]
    mov ecx, 1
    call emit_err

.lkh_loaded:
    lea rdi, [rel keyfile_buf]
    mov esi, eax
    lea rdx, [rel keyfile_hash]
    call sha256_hash

    lea rdi, [rel keyfile_buf]
    mov ecx, 256
    call zero_mem
    ret

; mlock_sensitive — pin sensitive buffers in RAM to prevent swap
mlock_sensitive:
    ; mlock the derived key buffer
    lea rdi, [rel derived_key]
    mov rsi, 32
    mov eax, SYS_MLOCK
    syscall

    ; mlock master password buffer
    lea rdi, [rel master_pw]
    mov rsi, 256
    mov eax, SYS_MLOCK
    syscall

    ; mlock entry data
    lea rdi, [rel entry_data]
    mov rsi, MAX_ENTRY_DATA
    mov eax, SYS_MLOCK
    syscall
    ret

; pack_entry_data — pack all fields into entry_data buffer
;   Returns: rax = packed data length
pack_entry_data:
    lea rdi, [rel entry_data]
    lea rsi, [rel entry_user]
    call strcpy_len
    add rdi, rax
    lea rsi, [rel entry_pass]
    call strcpy_len
    add rdi, rax
    lea rsi, [rel entry_url]
    call strcpy_len
    add rdi, rax
    lea rsi, [rel entry_notes]
    call strcpy_len
    add rdi, rax
    lea rsi, [rel entry_totp]
    call strcpy_len
    add rdi, rax
    lea rsi, [rel entry_data]
    sub rdi, rsi
    mov rax, rdi
    ret

; ════════════════════════════════════════════════════════════════
; Config & multi-vault helpers
; ════════════════════════════════════════════════════════════════

; load_config — read ~/.vault/config and parse settings
;   Sets config_gen_len if "length=N" found
load_config:
    push rbx
    push rcx
    push rdx

    ; Build config path: take vault_path, replace "vault.enc" with "config"
    lea rdi, [rel config_path]
    lea rsi, [rel vault_path]
    call strcpy
    ; Find last '/' in config_path
    lea rdi, [rel config_path]
    call get_dir_part
    lea rdi, [rel config_path]
    add rdi, rax
    mov byte [rdi], '/'
    inc rdi
    mov byte [rdi], 'c'
    mov byte [rdi+1], 'o'
    mov byte [rdi+2], 'n'
    mov byte [rdi+3], 'f'
    mov byte [rdi+4], 'i'
    mov byte [rdi+5], 'g'
    mov byte [rdi+6], 0

    ; Try to read config file
    lea rdi, [rel config_path]
    lea rsi, [rel config_buf]
    mov edx, 511
    call read_file
    test eax, eax
    jz .lc_done             ; no config file, use defaults

    ; Null-terminate
    lea rdi, [rel config_buf]
    mov byte [rdi + rax], 0

    ; Parse "length=N"
    lea rdi, [rel config_buf]
    lea rsi, [rel conf_key_len]
    call find_config_value   ; rax = pointer to value string, 0 if not found
    test rax, rax
    jz .lc_done
    mov rdi, rax
    call atoi
    test eax, eax
    jz .lc_done
    cmp eax, 128
    jg .lc_done
    mov [rel config_gen_len], eax

.lc_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; find_config_value — find "key=" in config buffer, return pointer to value
;   rdi = config buffer, rsi = key string (e.g. "length=")
;   Returns: rax = pointer to value (after '='), or 0
find_config_value:
    push rbx
    push rcx
    push rdx
    mov rbx, rdi            ; config buf
    mov rcx, rsi            ; key

    ; Get key length
    mov rdi, rcx
    call strlen
    mov edx, eax            ; key_len

.fcv_line:
    cmp byte [rbx], 0
    je .fcv_notfound

    ; Compare key at current position
    mov rdi, rbx
    mov rsi, rcx
    push rcx
    push rdx
    mov ecx, edx
    call memcmp
    pop rdx
    pop rcx
    test eax, eax
    jz .fcv_found

    ; Skip to next line
.fcv_nextline:
    cmp byte [rbx], 0
    je .fcv_notfound
    cmp byte [rbx], 10
    je .fcv_gotline
    inc rbx
    jmp .fcv_nextline
.fcv_gotline:
    inc rbx
    jmp .fcv_line

.fcv_found:
    ; Return pointer to value (past the key)
    lea rax, [rbx + rdx]
    pop rdx
    pop rcx
    pop rbx
    ret

.fcv_notfound:
    xor eax, eax
    pop rdx
    pop rcx
    pop rbx
    ret

; build_named_vault_path — build path for named vault
;   Uses vault_name to construct ~/.vault-<name>/vault.enc
build_named_vault_path:
    push rbx
    push rcx

    ; Start with HOME
    ; Walk environment to find HOME=
    mov rax, [rel argc]
    ; argc/argv have been shifted, we need original envp
    ; Actually, vault_path already has HOME prefix from build_vault_path
    ; We'll rebuild from vault_path base

    ; Get HOME from existing vault_path (everything before /.vault)
    lea rdi, [rel vault_path]
    call strlen
    mov ecx, eax
    ; Find "/.vault" in vault_path
    lea rdi, [rel vault_path]
    xor ebx, ebx
.bnvp_scan:
    cmp ebx, ecx
    jge .bnvp_done
    cmp byte [rdi + rbx], '/'
    jne .bnvp_next
    cmp byte [rdi + rbx + 1], '.'
    jne .bnvp_next
    cmp byte [rdi + rbx + 2], 'v'
    jne .bnvp_next
    ; Found /.v — this is our HOME end
    ; Build new path: HOME + /.vault-<name>/vault.enc
    lea rdi, [rel vault_path]
    add rdi, rbx
    ; Append /.vault-
    lea rsi, [rel vault_dir_fmt]
    call strcpy
    lea rdi, [rel vault_path]
    call strlen
    lea rdi, [rel vault_path]
    add rdi, rax
    ; Append vault name
    lea rsi, [rel vault_name]
    call strcpy
    lea rdi, [rel vault_path]
    call strlen
    lea rdi, [rel vault_path]
    add rdi, rax
    ; Append /vault.enc
    mov byte [rdi], '/'
    mov byte [rdi+1], 'v'
    mov byte [rdi+2], 'a'
    mov byte [rdi+3], 'u'
    mov byte [rdi+4], 'l'
    mov byte [rdi+5], 't'
    mov byte [rdi+6], '.'
    mov byte [rdi+7], 'e'
    mov byte [rdi+8], 'n'
    mov byte [rdi+9], 'c'
    mov byte [rdi+10], 0
    jmp .bnvp_done
.bnvp_next:
    inc ebx
    jmp .bnvp_scan
.bnvp_done:
    pop rcx
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; Vault helpers
; ════════════════════════════════════════════════════════════════

; open_vault — read vault, prompt for master password, derive key, verify HMAC
open_vault:
    push r12
    push r15
    call mlock_sensitive
    call read_vault_file
    test rax, rax
    jz .no_vault_helper

    mov [rel vault_file_size], rax

    ; Bounds guard: minimum file size is 66 bytes for v1-v3 (header) or
    ; 78 bytes for v4 (62 header + 16 tag, empty body).
    cmp rax, 66
    jl .ov_corrupt

    ; v4 vaults have ciphertext at offset 62 — defer entry_count sanity to
    ; after AEAD decrypt. Skip the upper-bound check for v4.
    movzx ecx, word [rel vault_buf + 8]
    cmp ecx, VAULT_VERSION_V4
    je .ov_skip_count_check

    ; Reject claimed entry counts that obviously overrun the file.
    ; A minimum per-entry overhead is 4 (name_len) + 1 (name byte) + 4 (enc_len)
    ; + 16 (IV) + 0 (ciphertext may be empty) = 25 bytes. So an upper bound
    ; on entry_count is (file_size - 66) / 25 + 1. Use this as a sanity gate.
    mov ecx, [rel vault_buf + 62]   ; entry count
    mov rax, [rel vault_file_size]
    sub rax, 66
    add rax, 24                      ; round up: (size-66+24)/25
    mov r8, 25
    xor edx, edx
    div r8                           ; rax = upper bound on entry count
    cmp ecx, eax
    ja .ov_corrupt
.ov_skip_count_check:

    ; Check for active session first
    call try_load_session
    test eax, eax
    jnz .ov_session_loaded

    ; No session — check VAULT_PASS env var first
    call try_env_pass
    test eax, eax
    jnz .ov_have_pass

    ; No env var — prompt interactively
    lea rdi, [rel prompt_master]
    lea rsi, [rel master_pw]
    mov edx, 255
    call read_password
.ov_have_pass:
    ; Get pw length
    lea rdi, [rel master_pw]
    call strlen
    mov r12, rax

    ; Get salt from vault header (offset 10)
    lea rsi, [rel vault_buf]
    add rsi, 10
    lea rdi, [rel vault_salt]
    mov ecx, SALT_LEN
    rep movsb

    ; Derive key — detect KDF from vault version
    ; Version is at vault_buf offset 8 (after 8-byte magic)
    lea rsi, [rel vault_buf]
    movzx eax, word [rsi + 8]
    cmp ax, VAULT_VERSION_ARGON2
    je .ov_argon2
    cmp ax, VAULT_VERSION_V3
    je .ov_argon2
    cmp ax, VAULT_VERSION_V4
    je .ov_argon2

    ; PBKDF2-SHA256 (legacy v1)
    lea rdi, [rel master_pw]
    mov rsi, r12
    lea rdx, [rel vault_salt]
    mov ecx, SALT_LEN
    mov r8d, dword [rel vault_buf + 26]
    test r8d, r8d
    jnz .ov_pbkdf2_iters_loaded
    mov r8d, PBKDF2_ITER
.ov_pbkdf2_iters_loaded:
    lea r9, [rel derived_key]
    call pbkdf2_sha256
    jmp .ov_kdf_done

.ov_argon2:
    ; Argon2id
    lea rdi, [rel master_pw]
    mov rsi, r12
    lea rdx, [rel vault_salt]
    mov ecx, SALT_LEN
    lea r8, [rel derived_key]
    call argon2id_hash

.ov_kdf_done:
    ; Apply keyfile if active
    cmp byte [rel keyfile_active], 0
    je .no_keyfile_apply
    call apply_keyfile
.no_keyfile_apply:

.ov_session_loaded:
    ; Verify integrity. Scope depends on version:
    ;   v1/v2: HMAC covers [62..end]
    ;   v3:    HMAC covers entire file with the HMAC slot [30..62) zeroed.
    ;   v4:    ChaCha20-Poly1305 AEAD over body, AAD = header[0..62].
    movzx eax, word [rel vault_buf + 8]
    mov   [rel g_vault_version], ax
    cmp ax, VAULT_VERSION_V4
    je .ov_verify_v4
    cmp eax, VAULT_VERSION_V3
    je .ov_verify_v3

    ; Legacy v1/v2 scope: [62..end]
    mov rax, [rel vault_file_size]
    sub rax, 62
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256
    jmp .ov_verify_compare

.ov_verify_v3:
    ; Save stored HMAC slot bytes, zero them, HMAC the whole file, restore.
    lea rdi, [rel saved_hmac_slot]
    lea rsi, [rel vault_buf + 30]
    mov ecx, 32
    rep movsb
    lea rdi, [rel vault_buf + 30]
    mov ecx, 32
    xor al, al
    rep stosb
    ; HMAC over [0..file_size]
    mov rax, [rel vault_file_size]
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256
    ; Restore the slot bytes for the compare below
    lea rdi, [rel vault_buf + 30]
    lea rsi, [rel saved_hmac_slot]
    mov ecx, 32
    rep movsb

.ov_verify_compare:
    ; Compare with stored HMAC — constant-time to deny timing side-channels.
    lea rdi, [rel vault_hmac]
    lea rsi, [rel vault_buf]
    add rsi, 30
    mov ecx, 32
    call ct_memcmp
    test eax, eax
    jnz .hmac_fail

    pop r15
    pop r12
    ret

.ov_verify_v4:
    ; AEAD-open the body in place. open_main_body_v4 returns 0 on success,
    ; -1 on tag mismatch.
    call open_main_body_v4
    test rax, rax
    jnz .hmac_fail
    pop r15
    pop r12
    ret

.no_vault_helper:
    lea rdi, [rel err_msg_no_vault]
    lea rsi, [rel err_code_no_vault]
    lea rdx, [rel msg_no_vault]
    mov ecx, 1
    call emit_err

.ov_corrupt:
    ; File too small or self-inconsistent — report as auth-failed (we don't want
    ; to leak whether the file looks tampered vs genuinely truncated).
    lea rdi, [rel err_msg_auth_failed]
    lea rsi, [rel err_code_auth_failed]
    lea rdx, [rel msg_hmac_fail]
    mov ecx, 1
    call emit_err

.hmac_fail:
    call zero_sensitive
    lea rdi, [rel err_msg_auth_failed]
    lea rsi, [rel err_code_auth_failed]
    lea rdx, [rel msg_hmac_fail]
    mov ecx, 1
    call emit_err

; read_vault_file — read vault file into vault_buf
;   Returns: rax = bytes read (0 if file doesn't exist)
read_vault_file:
    lea rdi, [rel vault_path]
    call file_exists
    test eax, eax
    jz .rvf_no
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, BUF_SIZE
    call read_file
    ret
.rvf_no:
    xor eax, eax
    ret

; find_entry — find entry by name in vault_buf
;   rdi = name to find (null-terminated)
;   Returns: rax = pointer to entry start (0 if not found)
find_entry:
    push rbx
    push rcx
    push rdx
    push rsi
    push r12

    mov r12, rdi            ; name to find
    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]     ; entry count
    test eax, eax
    jz .fe_notfound

    mov ecx, eax
    add rsi, 66             ; first entry

.fe_loop:
    test ecx, ecx
    jz .fe_notfound
    push rcx
    push rsi

    ; Compare name: must match BOTH length and bytes exactly.
    ; Bug fix: previous implementation accidentally used strlen(search) as the
    ; compare length, causing "foo" to exact-match "foo-bar". Now we first
    ; check lengths are equal, then memcmp.
    mov eax, [rsi]          ; entry name_len (from header)
    add rsi, 4              ; rsi -> entry name data
    push rax                ; save entry name_len for memcmp count
    mov rdi, r12
    call strlen             ; eax = strlen(search)
    pop rdx                 ; rdx = entry name_len
    cmp eax, edx
    jne .fe_next
    ; Lengths match — compare bytes.
    mov rdi, r12            ; search name
    mov rcx, rdx            ; length to compare
    call memcmp_n
    test eax, eax
    jnz .fe_next

    ; Found! Return pointer to entry start
    pop rax                 ; entry start (from push rsi above)
    pop rcx
    jmp .fe_done

.fe_next:
    pop rsi                 ; entry start
    ; Skip to next entry
    mov eax, [rsi]          ; name_len
    add rsi, 4
    add rsi, rax            ; skip name
    mov eax, [rsi]          ; enc_data_len
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax            ; skip IV + encrypted data
    pop rcx
    dec ecx
    jmp .fe_loop

.fe_notfound:
    xor eax, eax
.fe_done:
    pop r12
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; decrypt_entry — decrypt entry data into field buffers
;   rsi = pointer to entry start in vault_buf (at name_len field)
decrypt_entry:
    push rbx
    push r12
    push r13

    ; Skip name
    mov eax, [rsi]          ; name_len
    add rsi, 4
    add rsi, rax            ; skip name

    ; Encrypted data length
    mov r12d, [rsi]         ; enc_data_len
    add rsi, 4

    ; IV (16 bytes)
    mov rdi, rsi
    add rsi, IV_LEN

    ; Decrypt
    push rsi                ; encrypted data ptr
    mov rsi, rdi            ; IV
    lea rdi, [rel derived_key]
    pop rdx                 ; encrypted data
    mov ecx, r12d            ; enc_data_len (zero-extends to rcx)
    lea r8, [rel entry_data]
    call ctr_crypt

    ; Parse null-separated fields from entry_data
    lea rsi, [rel entry_data]

    lea rdi, [rel entry_user]
    call strcpy
    call strlen_from         ; advance rsi past the string + null
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_pass]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_url]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    lea rdi, [rel entry_notes]
    call strcpy
    mov rdi, rsi
    call strlen
    add rsi, rax
    inc rsi

    ; TOTP field (may not exist in old entries — check bounds)
    ; If we've consumed all decrypted data, totp is empty
    lea rdi, [rel entry_data]
    add rdi, r12             ; end of decrypted data (r12 = enc_data_len)
    cmp rsi, rdi
    jge .de_no_totp
    lea rdi, [rel entry_totp]
    call strcpy
    jmp .de_done
.de_no_totp:
    mov byte [rel entry_totp], 0
.de_done:

    pop r13
    pop r12
    pop rbx
    ret

; get_entry_size — calculate total size of one entry
;   rsi = pointer to entry start
;   Returns: rax = total entry size in bytes
get_entry_size:
    mov eax, [rsi]          ; name_len
    lea eax, [eax + 4]      ; + name_len field
    mov ecx, [rsi + rax]    ; enc_data_len (at name_len + 4 + name)
    ; Wait, let me recalculate
    mov eax, [rsi]          ; name_len
    mov ecx, eax
    add ecx, 4              ; past name_len + name
    mov eax, [rsi + rcx]    ; enc_data_len
    add ecx, 4              ; past enc_data_len field
    add ecx, IV_LEN         ; past IV
    add ecx, eax            ; past encrypted data
    mov eax, ecx             ; zero-extends to rax
    ret

; append_entry_and_save — append current entry (in entry_name, crypt_buf, iv_buf)
;   Uses: entry_name, crypt_buf (encrypted data), iv_buf, r14 (plaintext len = enc len)
append_entry_and_save:
    push rbx
    push r12

    ; Find end of current entries
    lea rdi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    add rdi, rax            ; end of current data

    ; Append new entry
    ; name_len (4 bytes)
    lea rsi, [rel entry_name]
    push rdi
    mov rdi, rsi
    call strlen
    pop rdi
    mov [rdi], eax
    mov r12d, eax           ; save name_len
    add rdi, 4

    ; name (N bytes)
    lea rsi, [rel entry_name]
    mov ecx, r12d
    rep movsb

    ; encrypted data length (4 bytes)
    mov eax, r14d
    mov [rdi], eax
    add rdi, 4

    ; IV (16 bytes)
    lea rsi, [rel iv_buf]
    mov ecx, IV_LEN
    rep movsb

    ; Encrypted data
    lea rsi, [rel crypt_buf]
    mov ecx, r14d
    rep movsb

    ; Update file size
    lea rax, [rel vault_buf]
    sub rdi, rax
    mov [rel vault_file_size], rdi

    ; Increment entry count
    lea rdi, [rel vault_buf]
    inc dword [rdi + 62]

    ; Recompute HMAC and save
    call recalc_and_save

    pop r12
    pop rbx
    ret

; recalc_and_save — recompute HMAC over data and write vault file
recalc_and_save:
    push rbx

    ; Recalculate file size from entries
    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]     ; entry count
    mov ecx, eax
    lea rdx, [rsi + 66]     ; first entry
    xor ebx, ebx            ; accumulated entries size
.recalc_loop:
    test ecx, ecx
    jz .recalc_done
    mov eax, [rdx]          ; name_len
    add edx, 4
    add edx, eax            ; skip name
    mov eax, [rdx]          ; enc_data_len
    add edx, 4
    add edx, IV_LEN
    add edx, eax
    dec ecx
    jmp .recalc_loop
.recalc_done:
    lea rax, [rel vault_buf]
    sub rdx, rax
    mov [rel vault_file_size], rdx

    ; Integrity by version:
    ;   v1/v2: HMAC-SHA256 over [62..end]
    ;   v3:    HMAC-SHA256 over full file with HMAC slot zeroed
    ;   v4:    ChaCha20-Poly1305 AEAD over body, header=AAD
    movzx eax, word [rel vault_buf + 8]
    cmp eax, VAULT_VERSION_V4
    je .rs_aead_v4
    cmp eax, VAULT_VERSION_V3
    je .rs_hmac_v3

    ; Legacy: HMAC over data from offset 62 to end
    mov rax, [rel vault_file_size]
    sub rax, 62
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256
    jmp .rs_hmac_done

.rs_hmac_v3:
    ; Zero HMAC slot, HMAC entire file
    lea rdi, [rel vault_buf + 30]
    mov ecx, 32
    xor al, al
    rep stosb
    mov rax, [rel vault_file_size]
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256

.rs_hmac_done:
    ; Copy HMAC to header at offset 30
    lea rdi, [rel vault_buf]
    add rdi, 30
    lea rsi, [rel vault_hmac]
    mov ecx, 32
    rep movsb

.rs_write_file:
    ; Write file
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov rax, [rel vault_file_size]
    mov edx, eax
    mov ecx, 0o600
    call write_file

    pop rbx
    ret

.rs_aead_v4:
    ; vault_file_size currently = 62 + plain_len (header + plaintext body).
    ; Compute plain_len, then seal_main_body_v4 generates nonce, encrypts in
    ; place, appends tag, and updates vault_file_size to 62 + plain_len + 16.
    mov rdi, [rel vault_file_size]
    sub rdi, 62                      ; plain_len
    call seal_main_body_v4
    jmp .rs_write_file

; zero_sensitive — zero all sensitive buffers
zero_sensitive:
    lea rdi, [rel master_pw]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel master_pw2]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel derived_key]
    mov ecx, 32
    call zero_mem
    lea rdi, [rel entry_data]
    mov ecx, MAX_ENTRY_DATA
    call zero_mem
    lea rdi, [rel entry_pass]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    lea rdi, [rel entry_totp]
    mov ecx, MAX_FIELD_LEN
    call zero_mem
    ret

; gen_password — generate random password
;   rdi = output buffer, rsi = length
gen_password:
    push rbx
    push r12
    push r13
    mov r12, rdi            ; output
    mov r13, rsi            ; length

    ; Get random bytes
    mov rdi, r12
    mov rsi, r13
    call get_random

    ; Map to charset
    xor ecx, ecx
.gen_loop:
    cmp rcx, r13
    jge .gen_done
    movzx eax, byte [r12 + rcx]
    xor edx, edx
    mov ebx, gen_charset_len
    div ebx                 ; edx = remainder
    lea rdi, [rel gen_charset]
    mov al, [rdi + rdx]
    mov [r12 + rcx], al
    inc ecx
    jmp .gen_loop
.gen_done:
    mov byte [r12 + r13], 0 ; null terminate
    pop r13
    pop r12
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; L2 helper functions
; ════════════════════════════════════════════════════════════════

; find_entry_fuzzy — find entry by exact match first, then substring
;   rdi = search term (null-terminated)
;   Returns: rax = pointer to entry start (0 if not found)
find_entry_fuzzy:
    push r12
    push r13

    mov r12, rdi            ; search term

    ; Try exact match first
    call find_entry
    test rax, rax
    jnz .fef_done

    ; Substring search
    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz .fef_notfound

    mov ecx, eax
    add rsi, 66

.fef_loop:
    test ecx, ecx
    jz .fef_notfound
    push rcx
    push rsi

    mov eax, [rsi]          ; name_len
    mov r13d, eax
    add rsi, 4              ; name data

    ; Check substring match
    mov rdi, r12            ; search term
    ; rsi = name data, r13d = name_len
    call substr_match
    test eax, eax
    jz .fef_next

    ; Found! Return entry start
    pop rax                 ; entry start
    pop rcx
    jmp .fef_done

.fef_next:
    pop rsi
    mov eax, [rsi]
    add rsi, 4
    add rsi, rax
    mov eax, [rsi]
    add rsi, 4
    add rsi, IV_LEN
    add rsi, rax
    pop rcx
    dec ecx
    jmp .fef_loop

.fef_notfound:
    xor eax, eax
.fef_done:
    pop r13
    pop r12
    ret

; substr_match — check if search term is a substring of name
;   rdi = search term (null-terminated)
;   rsi = name data (not null-terminated, length in r13d for context)
;   Returns: eax = 1 if match, 0 if not
substr_match:
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    mov r8, rdi             ; search term
    mov r9, rsi             ; name data

    ; Get search term length
    call strlen
    mov ecx, eax            ; search len
    test ecx, ecx
    jz .sm_yes              ; empty search matches everything

    ; For each position in name where substring could start
    mov edx, r13d
    sub edx, ecx
    js .sm_no               ; name shorter than search term
    inc edx                 ; number of positions to try

    xor ebx, ebx           ; position
.sm_pos:
    cmp ebx, edx
    jge .sm_no

    ; Compare search term with name at position ebx
    push rbx
    push rcx
    xor eax, eax           ; match flag
.sm_cmp:
    test ecx, ecx
    jz .sm_match
    movzx eax, byte [r8]
    ; Case-insensitive: tolower both
    cmp al, 'A'
    jb .sm_c1
    cmp al, 'Z'
    ja .sm_c1
    add al, 32
.sm_c1:
    movzx ebx, byte [r9]
    cmp bl, 'A'
    jb .sm_c2
    cmp bl, 'Z'
    ja .sm_c2
    add bl, 32
.sm_c2:
    cmp al, bl
    jne .sm_nomatch
    inc r8
    inc r9
    dec ecx
    jmp .sm_cmp

.sm_match:
    pop rcx
    pop rbx
    jmp .sm_yes

.sm_nomatch:
    pop rcx
    pop rbx
    ; Restore r8 to search term start, advance r9
    mov r8, rdi
    mov r9, rsi
    inc ebx
    add r9, rbx
    jmp .sm_pos

.sm_no:
    xor eax, eax
    jmp .sm_ret
.sm_yes:
    mov eax, 1
.sm_ret:
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; print_strength — print password strength indicator
;   rdi = password string
print_strength:
    push rbx
    push rcx

    call strlen
    mov ecx, eax            ; length

    ; Score: length + variety
    xor ebx, ebx           ; score
    ; Length score: 0-7=0, 8-11=1, 12-15=2, 16+=3
    cmp ecx, 8
    jl .ps_variety
    inc ebx
    cmp ecx, 12
    jl .ps_variety
    inc ebx
    cmp ecx, 16
    jl .ps_variety
    inc ebx

.ps_variety:
    ; Check character classes
    push rdi
    xor edx, edx           ; class flags: bit0=lower, bit1=upper, bit2=digit, bit3=special
.ps_scan:
    movzx eax, byte [rdi]
    test al, al
    jz .ps_count
    cmp al, 'a'
    jb .ps_not_lower
    cmp al, 'z'
    ja .ps_not_lower
    or edx, 1
    jmp .ps_next
.ps_not_lower:
    cmp al, 'A'
    jb .ps_not_upper
    cmp al, 'Z'
    ja .ps_not_upper
    or edx, 2
    jmp .ps_next
.ps_not_upper:
    cmp al, '0'
    jb .ps_special
    cmp al, '9'
    ja .ps_special
    or edx, 4
    jmp .ps_next
.ps_special:
    or edx, 8
.ps_next:
    inc rdi
    jmp .ps_scan

.ps_count:
    pop rdi
    ; Count set bits in edx (number of character classes)
    xor ecx, ecx
    test edx, 1
    jz .ps_b1
    inc ecx
.ps_b1:
    test edx, 2
    jz .ps_b2
    inc ecx
.ps_b2:
    test edx, 4
    jz .ps_b3
    inc ecx
.ps_b3:
    test edx, 8
    jz .ps_b4
    inc ecx
.ps_b4:
    add ebx, ecx           ; total score = length_score + variety_count

    ; Map score: 0-2=weak, 3-4=fair, 5-6=good, 7=strong
    cmp ebx, 3
    jl .ps_weak
    cmp ebx, 5
    jl .ps_fair
    cmp ebx, 7
    jl .ps_good
    lea rdi, [rel msg_strength_strong]
    jmp .ps_print
.ps_weak:
    lea rdi, [rel msg_strength_weak]
    jmp .ps_print
.ps_fair:
    lea rdi, [rel msg_strength_fair]
    jmp .ps_print
.ps_good:
    lea rdi, [rel msg_strength_good]
.ps_print:
    call print_str
    pop rcx
    pop rbx
    ret

; read_line_noprompt — read a line from stdin with no prompt
;   rsi = output buffer, edx = max length
;   Returns: rax = bytes read
read_line_noprompt:
    push r12
    push r13
    mov r12, rsi
    mov r13d, edx

    xor r14d, r14d
.rlnp_byte:
    cmp r14d, r13d
    jge .rlnp_done
    lea rsi, [r12 + r14]
    mov edi, STDIN
    mov edx, 1
    mov eax, SYS_READ
    syscall
    test eax, eax
    jle .rlnp_done
    cmp byte [r12 + r14], 10
    je .rlnp_strip
    inc r14d
    jmp .rlnp_byte
.rlnp_strip:
    mov byte [r12 + r14], 0
    mov eax, r14d
    jmp .rlnp_ret
.rlnp_done:
    mov byte [r12 + r14], 0
    mov eax, r14d
.rlnp_ret:
    pop r13
    pop r12
    ret

; ════════════════════════════════════════════════════════════════
; L3 helper functions
; ════════════════════════════════════════════════════════════════

; base32_decode — decode base32 string to raw bytes
;   rdi = base32 input (null-terminated, may have spaces/dashes/padding)
;   rsi = output buffer
;   Returns: eax = number of decoded bytes
base32_decode:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    mov r8, rdi             ; input
    mov r9, rsi             ; output
    xor r10d, r10d          ; output byte count
    xor ecx, ecx            ; accumulated bits
    xor edx, edx            ; bit count

.b32_loop:
    movzx eax, byte [r8]
    inc r8
    test al, al
    jz .b32_done
    cmp al, '='             ; padding
    je .b32_done
    cmp al, ' '             ; skip spaces
    je .b32_loop
    cmp al, '-'             ; skip dashes
    je .b32_loop

    ; Convert to 5-bit value
    cmp al, 'A'
    jb .b32_check_lower
    cmp al, 'Z'
    ja .b32_check_digit
    sub al, 'A'             ; A-Z = 0-25
    jmp .b32_got_val
.b32_check_lower:
    cmp al, 'a'
    jb .b32_check_digit
    cmp al, 'z'
    ja .b32_check_digit
    sub al, 'a'             ; a-z = 0-25
    jmp .b32_got_val
.b32_check_digit:
    cmp al, '2'
    jb .b32_loop            ; invalid char, skip
    cmp al, '7'
    ja .b32_loop
    sub al, '2'
    add al, 26              ; 2-7 = 26-31
.b32_got_val:
    ; Accumulate 5 bits
    movzx eax, al
    shl ecx, 5
    or ecx, eax
    add edx, 5

    ; If we have 8+ bits, output a byte
    cmp edx, 8
    jl .b32_loop
    sub edx, 8
    mov eax, ecx
    push rcx
    mov cl, dl
    shr eax, cl
    pop rcx
    mov [r9 + r10], al
    inc r10d
    ; Mask off the used bits
    mov eax, 1
    push rcx
    mov cl, dl
    shl eax, cl
    pop rcx
    dec eax
    and ecx, eax
    jmp .b32_loop

.b32_done:
    mov eax, r10d
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; itoa64 — convert 64-bit unsigned integer to decimal string
;   rax = value, rdi = output buffer
itoa64:
    push rbx
    push rcx
    push rdx
    mov rcx, 0
    mov rbx, 10
    test rax, rax
    jnz .i64_loop
    mov byte [rdi], '0'
    mov byte [rdi+1], 0
    pop rdx
    pop rcx
    pop rbx
    ret
.i64_loop:
    test rax, rax
    jz .i64_reverse
    xor edx, edx
    div rbx
    add dl, '0'
    push rdx
    inc rcx
    jmp .i64_loop
.i64_reverse:
    test rcx, rcx
    jz .i64_end
    pop rax
    mov [rdi], al
    inc rdi
    dec rcx
    jmp .i64_reverse
.i64_end:
    mov byte [rdi], 0
    pop rdx
    pop rcx
    pop rbx
    ret

; itoa_padded6 — convert integer to 6-digit zero-padded string
;   eax = value, rdi = output buffer
itoa_padded6:
    push rbx
    push rcx
    push rdx
    mov ecx, 6
    mov ebx, 10
    lea rdi, [rdi + 6]
    mov byte [rdi], 0       ; null terminate
.ip6_loop:
    test ecx, ecx
    jz .ip6_done
    dec rdi
    xor edx, edx
    div ebx
    add dl, '0'
    mov [rdi], dl
    dec ecx
    jmp .ip6_loop
.ip6_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; JSON/CSV import helpers
; ════════════════════════════════════════════════════════════════

; json_find_key — find a JSON key string in buffer
;   rdi = buffer position to search from
;   rsi = key to find (e.g. '"name"')
;   Returns: rax = pointer past the key and colon, 0 if not found
json_find_key:
    push rbx
    push rcx
    push rdx
    push r8

    mov r8, rdi             ; search start
    mov rbx, rsi            ; key

    ; Get key length
    mov rdi, rbx
    call strlen
    mov ecx, eax            ; key_len

.jfk_scan:
    cmp byte [r8], 0
    je .jfk_notfound

    ; Try matching key at current position
    mov rdi, r8
    mov rsi, rbx
    push rcx
    call memcmp
    pop rcx
    test eax, eax
    jz .jfk_found

    inc r8
    jmp .jfk_scan

.jfk_found:
    ; Skip past key
    add r8, rcx
    ; Skip whitespace and colon
.jfk_skip_ws:
    cmp byte [r8], 0
    je .jfk_notfound
    cmp byte [r8], ' '
    je .jfk_ws_next
    cmp byte [r8], 9
    je .jfk_ws_next
    cmp byte [r8], 10
    je .jfk_ws_next
    cmp byte [r8], 13
    je .jfk_ws_next
    cmp byte [r8], ':'
    je .jfk_colon
    jmp .jfk_got_value
.jfk_ws_next:
    inc r8
    jmp .jfk_skip_ws
.jfk_colon:
    inc r8
    ; Skip whitespace after colon
.jfk_skip_ws2:
    cmp byte [r8], ' '
    je .jfk_ws2_next
    cmp byte [r8], 9
    je .jfk_ws2_next
    cmp byte [r8], 10
    je .jfk_ws2_next
    cmp byte [r8], 13
    je .jfk_ws2_next
    jmp .jfk_got_value
.jfk_ws2_next:
    inc r8
    jmp .jfk_skip_ws2

.jfk_got_value:
    mov rax, r8
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

.jfk_notfound:
    xor eax, eax
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; json_extract_string_value — extract a JSON string value
;   rdi = pointer to start of value (should be at '"' or 'n' for null)
;   rsi = output buffer
;   Returns: rax = pointer past the value, 0 if error
;   Writes extracted string to output (or empty string for null)
json_extract_string_value:
    push rbx
    push rcx

    mov rbx, rdi            ; value start
    mov rcx, rsi            ; output

    ; Check for null
    cmp byte [rbx], 'n'
    jne .jesv_check_quote
    ; "null" — write empty string
    mov byte [rcx], 0
    add rbx, 4              ; skip "null"
    mov rax, rbx
    pop rcx
    pop rbx
    ret

.jesv_check_quote:
    cmp byte [rbx], '"'
    jne .jesv_err
    inc rbx                 ; skip opening quote

    ; Copy characters until closing quote
.jesv_copy:
    cmp byte [rbx], 0
    je .jesv_err
    cmp byte [rbx], '"'
    je .jesv_end
    cmp byte [rbx], '\'
    jne .jesv_normal

    ; Escape sequence
    inc rbx
    cmp byte [rbx], '"'
    je .jesv_esc_quote
    cmp byte [rbx], '\'
    je .jesv_esc_bs
    cmp byte [rbx], 'n'
    je .jesv_esc_n
    cmp byte [rbx], 't'
    je .jesv_esc_t
    ; Unknown escape, copy as-is
    mov al, [rbx]
    mov [rcx], al
    inc rcx
    inc rbx
    jmp .jesv_copy

.jesv_esc_quote:
    mov byte [rcx], '"'
    inc rcx
    inc rbx
    jmp .jesv_copy
.jesv_esc_bs:
    mov byte [rcx], '\'
    inc rcx
    inc rbx
    jmp .jesv_copy
.jesv_esc_n:
    mov byte [rcx], 10
    inc rcx
    inc rbx
    jmp .jesv_copy
.jesv_esc_t:
    mov byte [rcx], 9
    inc rcx
    inc rbx
    jmp .jesv_copy

.jesv_normal:
    mov al, [rbx]
    mov [rcx], al
    inc rcx
    inc rbx
    jmp .jesv_copy

.jesv_end:
    mov byte [rcx], 0       ; null-terminate
    inc rbx                 ; skip closing quote
    mov rax, rbx
    pop rcx
    pop rbx
    ret

.jesv_err:
    mov byte [rcx], 0
    xor eax, eax
    pop rcx
    pop rbx
    ret

; skip_to_newline — advance past next newline
;   rdi = current position
;   Returns: rax = position after newline, 0 if end of string
skip_to_newline:
.stn_loop:
    cmp byte [rdi], 0
    je .stn_end
    cmp byte [rdi], 10
    je .stn_found
    inc rdi
    jmp .stn_loop
.stn_found:
    inc rdi
    mov rax, rdi
    ret
.stn_end:
    xor eax, eax
    ret

; csv_extract_field — extract a CSV field (handles quoted fields)
;   rdi = current position in CSV data
;   rsi = output buffer
;   Returns: rax = position after field + delimiter, 0 if end
csv_extract_field:
    push rbx
    push rcx

    mov rbx, rdi            ; input
    mov rcx, rsi            ; output

    cmp byte [rbx], 0
    je .cef_end

    ; Check if quoted
    cmp byte [rbx], '"'
    je .cef_quoted

    ; Unquoted: copy until comma or newline or end
.cef_unquoted:
    cmp byte [rbx], 0
    je .cef_done_eof
    cmp byte [rbx], ','
    je .cef_done_comma
    cmp byte [rbx], 10
    je .cef_done_newline
    cmp byte [rbx], 13
    je .cef_done_newline
    mov al, [rbx]
    mov [rcx], al
    inc rbx
    inc rcx
    jmp .cef_unquoted

.cef_quoted:
    inc rbx                 ; skip opening quote
.cef_q_copy:
    cmp byte [rbx], 0
    je .cef_done_eof
    cmp byte [rbx], '"'
    je .cef_q_check
    mov al, [rbx]
    mov [rcx], al
    inc rbx
    inc rcx
    jmp .cef_q_copy

.cef_q_check:
    ; Check for escaped quote ("")
    cmp byte [rbx+1], '"'
    jne .cef_q_end
    ; Escaped quote
    mov byte [rcx], '"'
    inc rcx
    add rbx, 2
    jmp .cef_q_copy

.cef_q_end:
    inc rbx                 ; skip closing quote
    ; Skip delimiter after quote
    cmp byte [rbx], ','
    je .cef_done_comma
    cmp byte [rbx], 10
    je .cef_done_newline
    cmp byte [rbx], 13
    je .cef_done_newline
    jmp .cef_done_eof

.cef_done_comma:
    mov byte [rcx], 0
    inc rbx                 ; skip comma
    mov rax, rbx
    pop rcx
    pop rbx
    ret

.cef_done_newline:
    mov byte [rcx], 0
    inc rbx                 ; skip newline
    cmp byte [rbx], 10      ; handle \r\n
    jne .cef_ret_nl
    inc rbx
.cef_ret_nl:
    mov rax, rbx
    pop rcx
    pop rbx
    ret

.cef_done_eof:
    mov byte [rcx], 0
    mov rax, rbx
    pop rcx
    pop rbx
    ret

.cef_end:
    xor eax, eax
    pop rcx
    pop rbx
    ret

; ════════════════════════════════════════════════════════════════
; I/O and utility functions
; ════════════════════════════════════════════════════════════════

; print_str — print null-terminated string to stdout
;   rdi = string pointer
print_str:
    push rdi
    call strlen
    mov rdx, rax            ; length
    pop rsi                 ; buffer
    mov edi, STDOUT
    mov eax, SYS_WRITE
    syscall
    ret

; print_n — print N bytes to stdout
;   rdi = buffer, eax = length
print_n:
    mov rsi, rdi
    mov edx, eax
    mov edi, STDOUT
    mov eax, SYS_WRITE
    syscall
    ret

; print_err — write a null-terminated C-string to STDERR (fd 2)
;   rdi = buffer
print_err:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi
    mov edi, STDERR
    mov eax, SYS_WRITE
    syscall
    ret

; print_char_err — write single character to STDERR
;   al = character
print_char_err:
    push rax
    mov rsi, rsp
    mov edx, 1
    mov edi, STDERR
    mov eax, SYS_WRITE
    syscall
    pop rax
    ret

; print_json_quoted_err — like print_json_quoted but writes to STDERR
;   rdi = null-terminated string
print_json_quoted_err:
    push rbx
    mov rbx, rdi
    mov al, '"'
    call print_char_err
.pjqe_loop:
    mov al, [rbx]
    test al, al
    jz .pjqe_done
    cmp al, '"'
    je .pjqe_quote
    cmp al, 92
    je .pjqe_bs
    cmp al, 10
    je .pjqe_nl
    cmp al, 13
    je .pjqe_cr
    cmp al, 9
    je .pjqe_tab
    cmp al, 0x20
    jl .pjqe_skip            ; drop other control chars rather than emit invalid JSON
    call print_char_err
    jmp .pjqe_next
.pjqe_quote:
    mov al, 92
    call print_char_err
    mov al, '"'
    call print_char_err
    jmp .pjqe_next
.pjqe_bs:
    mov al, 92
    call print_char_err
    mov al, 92
    call print_char_err
    jmp .pjqe_next
.pjqe_nl:
    mov al, 92
    call print_char_err
    mov al, 'n'
    call print_char_err
    jmp .pjqe_next
.pjqe_cr:
    mov al, 92
    call print_char_err
    mov al, 'r'
    call print_char_err
    jmp .pjqe_next
.pjqe_tab:
    mov al, 92
    call print_char_err
    mov al, 't'
    call print_char_err
    jmp .pjqe_next
.pjqe_skip:
.pjqe_next:
    inc rbx
    jmp .pjqe_loop
.pjqe_done:
    mov al, '"'
    call print_char_err
    pop rbx
    ret

; argv_scan_exact_mode — return 1 in eax if --raw, --json, or --exact is in argv.
; Used to force exact (non-fuzzy) entry lookup whenever the caller is an agent
; (i.e. asked for structured output or explicit exact matching).
argv_scan_exact_mode:
    push rbx
    push r12
    push r13
    xor eax, eax
    mov r12, [rel argc]
    mov r13, 1
.asem_loop:
    cmp r13, r12
    jge .asem_done
    mov rax, [rel argv]
    mov rdi, [rax + r13*8]
    test rdi, rdi
    jz .asem_next
    lea rsi, [rel raw_flag]
    call strcmp
    test eax, eax
    jz .asem_yes
    mov rax, [rel argv]
    mov rdi, [rax + r13*8]
    lea rsi, [rel json_flag]
    call strcmp
    test eax, eax
    jz .asem_yes
    mov rax, [rel argv]
    mov rdi, [rax + r13*8]
    lea rsi, [rel exact_flag]
    call strcmp
    test eax, eax
    jz .asem_yes
.asem_next:
    inc r13
    jmp .asem_loop
.asem_yes:
    mov eax, 1
    jmp .asem_out
.asem_done:
    xor eax, eax
.asem_out:
    pop r13
    pop r12
    pop rbx
    ret

; argv_scan_raw_flag — return 1 in eax if --raw appears in argv[1..argc-1]
argv_scan_raw_flag:
    push rbx
    push r12
    push r13
    xor eax, eax
    mov r12, [rel argc]
    mov r13, 1
.asrf_loop:
    cmp r13, r12
    jge .asrf_done
    mov rax, [rel argv]
    mov rdi, [rax + r13*8]
    test rdi, rdi
    jz .asrf_next
    lea rsi, [rel raw_flag]
    call strcmp
    test eax, eax
    jnz .asrf_next
    mov eax, 1
    jmp .asrf_out
.asrf_next:
    inc r13
    jmp .asrf_loop
.asrf_done:
    xor eax, eax
.asrf_out:
    pop r13
    pop r12
    pop rbx
    ret

; emit_ok_simple — emit a success token then exit 0.
;   rdi = legacy human-readable message (used in plain mode)
; Decision: --json → {"ok":true}; --raw → "ok"; otherwise human message.
emit_ok_simple:
    push rdi
    cmp byte [rel output_json], 0
    jne .eos_json
    call argv_scan_json_flag
    test eax, eax
    jnz .eos_json
    cmp byte [rel output_raw], 0
    jne .eos_raw
    call argv_scan_raw_flag
    test eax, eax
    jnz .eos_raw
    pop rdi
    call print_str
    xor edi, edi
    call exit
.eos_raw:
    pop rdi
    lea rdi, [rel msg_ok_raw]
    call print_str
    xor edi, edi
    call exit
.eos_json:
    pop rdi
    lea rdi, [rel json_ok_true]
    call print_str
    xor edi, edi
    call exit

; argv_scan_json_flag — return 1 in eax if --json appears in argv[1..argc-1]
argv_scan_json_flag:
    push rbx
    push r12
    push r13
    xor eax, eax
    mov r12, [rel argc]
    mov r13, 1
.asjf_loop:
    cmp r13, r12
    jge .asjf_done
    mov rax, [rel argv]
    mov rdi, [rax + r13*8]
    test rdi, rdi
    jz .asjf_next
    lea rsi, [rel json_flag]
    call strcmp
    test eax, eax
    jnz .asjf_next
    mov eax, 1
    jmp .asjf_out
.asjf_next:
    inc r13
    jmp .asjf_loop
.asjf_done:
    xor eax, eax
.asjf_out:
    pop r13
    pop r12
    pop rbx
    ret

; emit_err — emit a structured or human-readable error to STDERR, then exit.
;   rdi = short error message (used inside JSON envelope; no trailing newline)
;   rsi = error code slug (machine-stable)
;   rdx = pointer to legacy human-readable message (may be NULL — falls back to rdi+newline)
;   ecx = exit code
emit_err:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi             ; short msg
    mov r12, rsi             ; code slug
    mov r13, rdx             ; legacy human msg
    mov r14d, ecx            ; exit code

    ; Decide JSON vs plain. Prefer the global flag if already set; otherwise scan argv.
    cmp byte [rel output_json], 0
    jne .emit_json
    call argv_scan_json_flag
    test eax, eax
    jnz .emit_json

    ; Plain path: human-readable text to STDERR.
    test r13, r13
    jz .emit_plain_short
    mov rdi, r13
    call print_err
    jmp .emit_exit
.emit_plain_short:
    mov rdi, rbx
    call print_err
    mov al, 10
    call print_char_err
    jmp .emit_exit

.emit_json:
    lea rdi, [rel json_err_prefix]
    call print_err
    mov rdi, r12
    call print_err           ; code slug (already JSON-safe: ascii lowercase/underscore)
    lea rdi, [rel json_err_middle]
    call print_err
    ; Emit the short message as a JSON string body (without surrounding quotes —
    ; print_json_quoted_err adds them, so use a manual inline loop instead).
    push rbx
    mov rbx, rbx             ; pointer to message
.emit_json_body:
    mov al, [rbx]
    test al, al
    jz .emit_json_body_done
    cmp al, '"'
    je .emit_json_q
    cmp al, 92
    je .emit_json_bs
    cmp al, 10
    je .emit_json_nl
    cmp al, 13
    je .emit_json_cr
    cmp al, 9
    je .emit_json_tab
    cmp al, 0x20
    jl .emit_json_skip
    call print_char_err
    jmp .emit_json_next
.emit_json_q:
    mov al, 92
    call print_char_err
    mov al, '"'
    call print_char_err
    jmp .emit_json_next
.emit_json_bs:
    mov al, 92
    call print_char_err
    mov al, 92
    call print_char_err
    jmp .emit_json_next
.emit_json_nl:
    mov al, 92
    call print_char_err
    mov al, 'n'
    call print_char_err
    jmp .emit_json_next
.emit_json_cr:
    mov al, 92
    call print_char_err
    mov al, 'r'
    call print_char_err
    jmp .emit_json_next
.emit_json_tab:
    mov al, 92
    call print_char_err
    mov al, 't'
    call print_char_err
    jmp .emit_json_next
.emit_json_skip:
.emit_json_next:
    inc rbx
    jmp .emit_json_body
.emit_json_body_done:
    pop rbx
    lea rdi, [rel json_err_suffix]
    call print_err

.emit_exit:
    mov edi, r14d
    call exit

; print_char — print single character
;   al = character
print_char:
    push rax
    mov rsi, rsp
    mov edx, 1
    mov edi, STDOUT
    mov eax, SYS_WRITE
    syscall
    pop rax
    ret

; print_json_quoted — print a null-terminated string as a JSON string literal
;   rdi = string
print_json_quoted:
    push rbx
    mov rbx, rdi
    mov al, '"'
    call print_char
.pjq_loop:
    mov al, [rbx]
    test al, al
    jz .pjq_done
    cmp al, '"'
    je .pjq_quote
    cmp al, 92
    je .pjq_bs
    cmp al, 10
    je .pjq_n
    cmp al, 13
    je .pjq_r
    cmp al, 9
    je .pjq_t
    call print_char
    inc rbx
    jmp .pjq_loop
.pjq_quote:
    lea rdi, [rel json_escape_quote]
    call print_str
    inc rbx
    jmp .pjq_loop
.pjq_bs:
    lea rdi, [rel json_escape_bs]
    call print_str
    inc rbx
    jmp .pjq_loop
.pjq_n:
    lea rdi, [rel json_escape_n]
    call print_str
    inc rbx
    jmp .pjq_loop
.pjq_r:
    lea rdi, [rel json_escape_r]
    call print_str
    inc rbx
    jmp .pjq_loop
.pjq_t:
    lea rdi, [rel json_escape_t]
    call print_str
    inc rbx
    jmp .pjq_loop
.pjq_done:
    mov al, '"'
    call print_char
    pop rbx
    ret

; print_json_quoted_n — print a length-delimited buffer as a JSON string literal
;   rdi = buffer, eax = length
print_json_quoted_n:
    push rbx
    push r12
    mov rbx, rdi
    mov r12d, eax
    mov al, '"'
    call print_char
.pjqn_loop:
    test r12d, r12d
    jz .pjqn_done
    mov al, [rbx]
    cmp al, '"'
    je .pjqn_quote
    cmp al, 92
    je .pjqn_bs
    cmp al, 10
    je .pjqn_n
    cmp al, 13
    je .pjqn_r
    cmp al, 9
    je .pjqn_t
    call print_char
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_quote:
    lea rdi, [rel json_escape_quote]
    call print_str
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_bs:
    lea rdi, [rel json_escape_bs]
    call print_str
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_n:
    lea rdi, [rel json_escape_n]
    call print_str
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_r:
    lea rdi, [rel json_escape_r]
    call print_str
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_t:
    lea rdi, [rel json_escape_t]
    call print_str
    inc rbx
    dec r12d
    jmp .pjqn_loop
.pjqn_done:
    mov al, '"'
    call print_char
    pop r12
    pop rbx
    ret

; parse_output_flags — parse trailing --raw / --json flags
;   rdi = starting argv index
parse_output_flags:
    push r12
    mov r12, rdi
    mov byte [rel output_raw], 0
    mov byte [rel output_json], 0
.pof_loop:
    mov rax, [rel argc]
    cmp r12, rax
    jge .pof_done
    mov rax, [rel argv]
    mov rdi, [rax + r12*8]
    lea rsi, [rel raw_flag]
    push r12
    call strcmp
    pop r12
    test eax, eax
    jnz .pof_check_json
    cmp byte [rel output_json], 0
    jne .pof_conflict
    mov byte [rel output_raw], 1
    inc r12
    jmp .pof_loop
.pof_check_json:
    mov rax, [rel argv]
    mov rdi, [rax + r12*8]
    lea rsi, [rel json_flag]
    push r12
    call strcmp
    pop r12
    test eax, eax
    jnz .pof_check_exact
    cmp byte [rel output_raw], 0
    jne .pof_conflict
    mov byte [rel output_json], 1
    inc r12
    jmp .pof_loop
.pof_check_exact:
    mov rax, [rel argv]
    mov rdi, [rax + r12*8]
    lea rsi, [rel exact_flag]
    push r12
    call strcmp
    pop r12
    test eax, eax
    jnz .pof_bad
    ; --exact composes with --raw/--json; no conflict, no state byte needed
    ; (lookup mode is recomputed from argv at call sites via argv_scan_exact_mode)
    inc r12
    jmp .pof_loop
.pof_bad:
    lea rdi, [rel err_msg_bad_output]
    lea rsi, [rel err_code_bad_output]
    lea rdx, [rel msg_output_opt]
    mov ecx, 2
    call emit_err
.pof_conflict:
    lea rdi, [rel err_msg_output_conflict]
    lea rsi, [rel err_code_output_conflict]
    lea rdx, [rel msg_output_conflict]
    mov ecx, 2
    call emit_err
.pof_done:
    pop r12
    ret

; print_hex — print N bytes as hex string
;   rdi = data, esi = byte count
print_hex:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    xor ecx, ecx
.hex_loop:
    cmp ecx, r13d
    jge .hex_done
    push rcx
    movzx eax, byte [r12 + rcx]
    mov ebx, eax
    shr eax, 4
    lea rdx, [rel hex_chars]
    mov al, [rdx + rax]
    call print_char
    mov eax, ebx
    and eax, 0x0f
    lea rdx, [rel hex_chars]
    mov al, [rdx + rax]
    call print_char
    pop rcx
    inc ecx
    jmp .hex_loop
.hex_done:
    pop r13
    pop r12
    pop rbx
    ret

; strlen — get string length
;   rdi = string, returns rax = length
strlen:
    push rcx
    push rdi
    xor ecx, ecx
.sl:
    cmp byte [rdi], 0
    je .sl_done
    inc rdi
    inc ecx
    jmp .sl
.sl_done:
    mov eax, ecx
    pop rdi
    pop rcx
    ret

; strlen_from — get string length from rsi
strlen_from:
    push rdi
    mov rdi, rsi
    call strlen
    pop rdi
    ret

; strcmp — compare two null-terminated strings
;   rdi = str1, rsi = str2
;   Returns: eax = 0 if equal
strcmp:
    push rbx
.sc:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne .sc_ne
    test al, al
    jz .sc_eq
    inc rdi
    inc rsi
    jmp .sc
.sc_eq:
    xor eax, eax
    pop rbx
    ret
.sc_ne:
    mov eax, 1
    pop rbx
    ret

; strcpy — copy null-terminated string
;   rdi = dest, rsi = src
strcpy:
    push rdi
    push rsi
.scp:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .scp_done
    inc rdi
    inc rsi
    jmp .scp
.scp_done:
    pop rsi
    pop rdi
    ret

; strcpy_len — copy null-terminated string, return length+1 (including null)
;   rdi = dest, rsi = src
;   Returns: rax = bytes copied including null terminator
strcpy_len:
    push rdi
    push rsi
    xor ecx, ecx
.scl:
    mov al, [rsi]
    mov [rdi], al
    inc ecx
    test al, al
    jz .scl_done
    inc rdi
    inc rsi
    jmp .scl
.scl_done:
    mov eax, ecx
    pop rsi
    pop rdi
    ret

; memcmp — compare N bytes
;   rdi = buf1, rsi = buf2, ecx = length
;   Returns: eax = 0 if equal
memcmp:
    push rbx
.mc:
    test ecx, ecx
    jz .mc_eq
    mov al, [rdi]
    cmp al, [rsi]
    jne .mc_ne
    inc rdi
    inc rsi
    dec ecx
    jmp .mc
.mc_eq:
    xor eax, eax
    pop rbx
    ret
.mc_ne:
    mov eax, 1
    pop rbx
    ret

; ct_memcmp — constant-time byte compare. Accumulates XOR-difference into al
; with no early exit, so timing reveals nothing about which byte mismatched.
;   rdi = a, rsi = b, ecx = length
;   Returns eax = 0 iff equal, nonzero otherwise.
; Use this for any secret-vs-supplied compare (HMAC tags, keyfile hashes).
ct_memcmp:
    push rbx
    xor eax, eax              ; accumulator
    test ecx, ecx
    jz .ctc_done
.ctc_loop:
    mov bl, [rdi]
    xor bl, [rsi]
    or al, bl
    inc rdi
    inc rsi
    dec ecx
    jnz .ctc_loop
.ctc_done:
    movzx eax, al
    pop rbx
    ret

; memcmp_n — compare rcx bytes (same as memcmp but uses rcx)
memcmp_n:
    jmp memcmp

; zero_mem — zero ecx bytes at rdi
zero_mem:
    push rdi
    xor al, al
    rep stosb
    pop rdi
    ret

; read_line — print prompt and read a line from stdin
;   rdi = prompt string, rsi = output buffer, edx = max length
;   Returns: rax = bytes read (without newline)
read_line:
    push r12
    push r13
    push r14
    mov r12, rsi            ; output buffer
    mov r13d, edx           ; max len
    ; Prompts go to STDERR so stdout stays clean for piping.
    call print_err

    ; Read one byte at a time until newline or EOF
    xor r14d, r14d          ; bytes read
.rl_byte:
    cmp r14d, r13d
    jge .rl_done
    lea rsi, [r12 + r14]
    mov edi, STDIN
    mov edx, 1
    mov eax, SYS_READ
    syscall
    test eax, eax
    jle .rl_done            ; EOF or error
    cmp byte [r12 + r14], 10  ; newline?
    je .rl_strip
    inc r14d
    jmp .rl_byte
.rl_strip:
    mov byte [r12 + r14], 0
    mov eax, r14d
    jmp .rl_ret
.rl_done:
    mov byte [r12 + r14], 0
    mov eax, r14d
.rl_ret:
    pop r14
    pop r13
    pop r12
    ret

; read_password — read with echo disabled
;   rdi = prompt, rsi = output buffer, edx = max length
;   Returns: rax = bytes read
read_password:
    push r12
    push r13
    push r14
    mov r12, rdi            ; prompt
    mov r13, rsi            ; output
    mov r14d, edx           ; max len

    ; Get current terminal settings
    mov edi, STDIN
    mov esi, TCGETS
    lea rdx, [rel old_termios]
    mov eax, SYS_IOCTL
    syscall

    ; Copy and disable echo
    lea rsi, [rel old_termios]
    lea rdi, [rel new_termios]
    mov ecx, 60
    rep movsb
    lea rdi, [rel new_termios]
    ; c_lflag is at offset 12 in termios struct
    mov eax, [rdi + 12]
    and eax, ~ECHO          ; disable echo
    mov [rdi + 12], eax

    ; Set new settings
    mov edi, STDIN
    mov esi, TCSETS
    lea rdx, [rel new_termios]
    mov eax, SYS_IOCTL
    syscall

    ; Read password
    mov rdi, r12
    mov rsi, r13
    mov edx, r14d
    call read_line
    push rax                ; save length

    ; Print newline (since echo was off) — to STDERR, mirroring the prompt.
    lea rdi, [rel msg_newline]
    call print_err

    ; Restore terminal
    mov edi, STDIN
    mov esi, TCSETS
    lea rdx, [rel old_termios]
    mov eax, SYS_IOCTL
    syscall

    pop rax
    pop r14
    pop r13
    pop r12
    ret

; file_exists — check if file exists
;   rdi = path
;   Returns: eax = 1 if exists, 0 if not
file_exists:
    mov esi, O_RDONLY
    mov eax, SYS_OPEN
    syscall
    test eax, eax
    js .fe_no
    ; File opened, close it
    mov edi, eax
    mov eax, SYS_CLOSE
    syscall
    mov eax, 1
    ret
.fe_no:
    xor eax, eax
    ret

; read_file — read file contents into buffer
;   rdi = path, rsi = buffer, edx = max size
;   Returns: rax = bytes read
read_file:
    push r12
    push r13
    push r14
    mov r12, rsi            ; buffer
    mov r13d, edx           ; max size

    mov esi, O_RDONLY
    mov eax, SYS_OPEN
    syscall
    test eax, eax
    js .rf_err

    mov edi, eax            ; fd
    mov r14, 0              ; total bytes read
.rf_read_loop:
    cmp r14d, r13d
    jge .rf_done_reading
    mov rsi, r12
    add rsi, r14
    mov edx, r13d
    sub edx, r14d
    mov eax, SYS_READ
    syscall
    test eax, eax
    js .rf_close_err
    jz .rf_done_reading
    add r14, rax
    jmp .rf_read_loop

.rf_done_reading:
    mov eax, SYS_CLOSE
    syscall
    mov rax, r14

    pop r14
    pop r13
    pop r12
    ret
.rf_close_err:
    push rdi
    mov eax, SYS_CLOSE
    syscall
    pop rdi
.rf_err:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    ret

; write_file — write buffer to file
;   rdi = path, rsi = data, edx = length, ecx = mode
write_file:
    push r12
    push r13
    push r14
    push r15
    mov r12, rsi            ; data
    mov r13d, edx           ; length
    mov r14d, ecx           ; mode

    mov esi, O_WRONLY | O_CREAT | O_TRUNC
    mov edx, r14d
    mov eax, SYS_OPEN
    syscall
    test eax, eax
    js .wf_err

    mov edi, eax            ; fd
    mov r15, 0              ; total bytes written
.wf_write_loop:
    cmp r15d, r13d
    jge .wf_close
    mov rsi, r12
    add rsi, r15
    mov edx, r13d
    sub edx, r15d
    mov eax, SYS_WRITE
    syscall
    test eax, eax
    js .wf_close
    test eax, eax
    jz .wf_close
    add r15, rax
    jmp .wf_write_loop

.wf_close:
    mov eax, SYS_CLOSE
    syscall
    mov rax, r15

.wf_err:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; get_random — fill buffer with random bytes
;   rdi = buffer, esi = count
; get_random(rdi=buf, rsi=count)
; Aborts the process on short read or syscall error — nonces / keys / IVs
; built on partial randomness would silently break ChaCha20-Poly1305
; (nonce reuse with the same key reveals plaintext-XOR and breaks the MAC).
; SysV syscall ABI preserves rsi, so we compare rax == rsi after the call.
get_random:
    xor     edx, edx                    ; flags = 0
    mov     eax, SYS_GETRANDOM
    syscall
    cmp     rax, rsi
    jne     .gr_fail
    ret
.gr_fail:
    mov     edi, 2                      ; stderr
    lea     rsi, [rel err_no_random]
    mov     edx, ERR_NO_RANDOM_LEN
    mov     eax, SYS_WRITE
    syscall
    mov     edi, 1
    mov     eax, SYS_EXIT
    syscall

; get_dir_part — find last / in path, return offset
;   rdi = path
;   Returns: rax = offset of last /
get_dir_part:
    push rbx
    call strlen
    mov ecx, eax
    xor ebx, ebx           ; last slash pos
.gdp:
    test ecx, ecx
    jz .gdp_done
    dec ecx
    cmp byte [rdi + rcx], '/'
    jne .gdp
    mov ebx, ecx
.gdp_done:
    mov eax, ebx
    pop rbx
    ret

; copy_until_tab — copy from rsi to rdi until tab or newline or null
;   Returns: rax = bytes consumed (including delimiter)
copy_until_tab:
    push rbx
    xor ecx, ecx
.cut:
    mov al, [rsi + rcx]
    cmp al, 9              ; tab
    je .cut_done
    cmp al, 10             ; newline
    je .cut_done
    cmp al, 0
    je .cut_done
    mov [rdi + rcx], al
    inc ecx
    jmp .cut
.cut_done:
    mov byte [rdi + rcx], 0 ; null terminate
    inc ecx                 ; skip delimiter
    mov eax, ecx
    pop rbx
    ret

; copy_until_newline — copy from rsi to rdi until newline or null
;   Returns: rax = bytes consumed (including delimiter)
copy_until_newline:
    xor ecx, ecx
.cun:
    mov al, [rsi + rcx]
    cmp al, 10
    je .cun_done
    cmp al, 0
    je .cun_done
    mov [rdi + rcx], al
    inc ecx
    jmp .cun
.cun_done:
    mov byte [rdi + rcx], 0
    inc ecx
    mov eax, ecx
    ret

; atoi — convert null-terminated decimal string to integer
;   rdi = string
;   Returns: eax = value
atoi:
    xor eax, eax
    xor ecx, ecx
.atoi_loop:
    movzx edx, byte [rdi + rcx]
    cmp dl, '0'
    jb .atoi_done
    cmp dl, '9'
    ja .atoi_done
    imul eax, 10
    sub dl, '0'
    add eax, edx
    inc ecx
    jmp .atoi_loop
.atoi_done:
    ret

; itoa — convert integer to null-terminated decimal string
;   eax = value, rdi = output buffer
itoa:
    push rbx
    push rcx
    push rdx
    mov ecx, 0              ; digit count
    mov ebx, 10
    test eax, eax
    jnz .itoa_loop
    mov byte [rdi], '0'
    mov byte [rdi+1], 0
    pop rdx
    pop rcx
    pop rbx
    ret
.itoa_loop:
    test eax, eax
    jz .itoa_reverse
    xor edx, edx
    div ebx
    add dl, '0'
    push rdx
    inc ecx
    jmp .itoa_loop
.itoa_reverse:
    test ecx, ecx
    jz .itoa_end
    pop rax
    mov [rdi], al
    inc rdi
    dec ecx
    jmp .itoa_reverse
.itoa_end:
    mov byte [rdi], 0
    pop rdx
    pop rcx
    pop rbx
    ret

; exit — exit with code
;   edi = exit code
exit:
    mov eax, SYS_EXIT
    syscall
