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

%define SESSION_TIMEOUT 300     ; 5 minutes default
%define SESSION_KEY_SIZE 32
%define SESSION_SALT_SIZE 16
; Session file stores: salt(16) + encrypted_key(32) = 48 bytes

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
msg_migrate_ok: db "Vault migrated to new format (with TOTP field).", 10, 0
msg_migrating:  db "Migrating entry: ", 0
cmd_test_sha:   db "test-sha256", 0

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

; ── Messages ─────────────────────────────────────────────────
msg_usage:      db "Usage: vault [--keyfile <path>] [--vault <name>] <command> [args]", 10
                db "Commands: init, add, get, list, gen, rm, export, import,", 10
                db "          show, search, count, edit, clip, totp, verify, backup,", 10
                db "          wipe, unlock, lock, hidden, migrate", 10, 0
msg_init_ok:    db "Vault created at ~/.vault/vault.enc", 10, 0
msg_init_exist: db "Error: vault already exists. Delete ~/.vault/vault.enc to reinitialize.", 10, 0
msg_no_vault:   db "Error: no vault found. Run 'vault init' first.", 10, 0
msg_mismatch:   db "Error: passwords do not match.", 10, 0
msg_added:      db "Entry added.", 10, 0
msg_removed:    db "Entry removed.", 10, 0
msg_not_found:  db "Error: entry not found.", 10, 0
msg_exists:     db "Error: entry already exists.", 10, 0
msg_no_name:    db "Error: name required.", 10, 0
msg_imported:   db " entries imported.", 10, 0
msg_empty:      db "Vault is empty.", 10, 0
msg_generated:  db "Generated password stored.", 10, 0
msg_hmac_fail:  db "Error: HMAC verification failed. Wrong password or corrupted vault.", 10, 0
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
msg_totp_hint:  db "Use 'vault edit <name>' and add TOTP secret as notes field (base32).", 10, 0
msg_wipe_confirm: db "Type 'DESTROY' to permanently wipe the vault: ", 0
msg_wipe_ok:    db "Vault securely wiped.", 10, 0
msg_wipe_abort: db "Wipe aborted.", 10, 0
msg_mlock_ok:   db 0    ; silent
wipe_confirm:   db "DESTROY", 0
keyfile_flag:   db "--keyfile", 0
argon2_flag:    db "--argon2", 0
msg_argon2_init: db "Vault created with Argon2id (16 MiB, 3 iterations).", 10, 0
msg_argon2_kdf:  db 0   ; silent marker

%define VAULT_VERSION_ARGON2 0x0002
vault_flag:     db "--vault", 0
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
session_path_prefix: db "/tmp/.vault-session-", 0

; ── Hidden vault messages ────────────────────────────────────
msg_hidden_init:    db "Hidden vault initialized within main vault.", 10, 0
msg_hidden_pw:      db "Hidden password: ", 0
msg_hidden_add:     db "Entry added to hidden vault.", 10, 0
msg_hidden_usage:   db "Usage: vault hidden <init|add|get|list|rm> [args]", 10, 0
msg_hidden_empty:   db "Hidden vault is empty.", 10, 0
hidden_marker:  db "NYXHIDE", 0

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
session_path:   resb 128        ; /tmp/.vault-session-<uid>
session_buf:    resb 64         ; session file buffer
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
entry_name:     resb MAX_NAME_LEN
entry_user:     resb MAX_FIELD_LEN
entry_pass:     resb MAX_FIELD_LEN
entry_url:      resb MAX_FIELD_LEN
entry_notes:    resb MAX_FIELD_LEN
entry_totp:     resb MAX_FIELD_LEN
entry_data:     resb MAX_ENTRY_DATA
crypt_buf:      resb MAX_ENTRY_DATA
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

    ; Build vault path from HOME env
    call build_vault_path

    ; Check argc >= 2
    mov rax, [rel argc]
    cmp rax, 2
    jl .show_usage

    ; Check for --argon2 flag (no-arg flag, just shifts by 1)
    mov byte [rel argon2_use_argon2], 0
    mov rax, [rel argv]
    mov rdi, [rax+8]
    lea rsi, [rel argon2_flag]
    call strcmp
    test eax, eax
    jnz .no_argon2_flag
    mov byte [rel argon2_use_argon2], 1
    mov rax, [rel argc]
    dec rax
    mov [rel argc], rax
    mov rax, [rel argv]
    add rax, 8
    mov [rel argv], rax
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
    jl .show_usage

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
    jl .show_usage

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

.show_usage:
    lea rdi, [rel msg_usage]
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
; CTR mode encrypt/decrypt (SHA-256 keystream XOR)
;   rdi = key (32 bytes), rsi = iv (16 bytes)
;   rdx = input, rcx = input_len, r8 = output
; ════════════════════════════════════════════════════════════════
ctr_crypt:
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
; Vault Commands
; ════════════════════════════════════════════════════════════════

; ── vault init ───────────────────────────────────────────────
do_init:
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

    ; Version (2 bytes) — 0x0001 for PBKDF2, 0x0002 for Argon2id
    cmp byte [rel argon2_use_argon2], 0
    je .init_ver_pbkdf2
    mov word [rdi], VAULT_VERSION_ARGON2
    jmp .init_ver_done
.init_ver_pbkdf2:
    mov word [rdi], VAULT_VERSION
.init_ver_done:
    add rdi, 2

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

    ; Simpler: HMAC position is at offset 30 (8+2+16+4)
    ; Data to HMAC starts at offset 62 (30+32), covers entry_count + entries
    ; Total size so far = 8+2+16+4+32+4 = 66
    lea rdi, [rel derived_key]   ; key
    mov rsi, 32                  ; key_len
    lea rdx, [rel vault_buf]
    add rdx, 62                  ; data starts after HMAC
    mov rcx, 4                   ; just entry_count (0 entries)
    lea r8, [rel vault_hmac]
    call hmac_sha256

    ; Copy HMAC into buffer at offset 30
    pop rdi                 ; was HMAC position, but let's just use offset
    lea rdi, [rel vault_buf]
    add rdi, 30
    lea rsi, [rel vault_hmac]
    mov ecx, HMAC_LEN
    rep movsb

    ; Write file
    lea rdi, [rel vault_path]
    lea rsi, [rel vault_buf]
    mov edx, 66            ; total: 8+2+16+4+32+4 = 66
    mov ecx, 0o600
    call write_file

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
    lea rdi, [rel msg_init_exist]
    call print_str
    mov edi, 1
    call exit

.init_mismatch:
    lea rdi, [rel msg_mismatch]
    call print_str
    lea rdi, [rel master_pw]
    mov ecx, 256
    call zero_mem
    lea rdi, [rel master_pw2]
    mov ecx, 256
    call zero_mem
    mov edi, 1
    call exit

; ── Common error handlers (global labels for cross-function jumps) ──
err_no_vault:
    lea rdi, [rel msg_no_vault]
    call print_str
    mov edi, 1
    call exit

err_need_name:
    lea rdi, [rel msg_no_name]
    call print_str
    mov edi, 1
    call exit

err_not_found:
    call zero_sensitive
    lea rdi, [rel msg_not_found]
    call print_str
    mov edi, 1
    call exit

err_entry_exists:
    call zero_sensitive
    lea rdi, [rel msg_exists]
    call print_str
    mov edi, 1
    call exit

err_list_empty:
    lea rdi, [rel msg_empty]
    call print_str
    xor edi, edi
    call exit

; ── vault list ───────────────────────────────────────────────
do_list:
    ; Read vault file
    call read_vault_file    ; rax = bytes read, data in vault_buf
    test rax, rax
    jz err_no_vault

    ; Parse entry count at offset 62
    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz err_list_empty

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

    ; Read vault, verify master password
    call open_vault         ; derives key, verifies HMAC

    ; Check entry doesn't already exist
    lea rdi, [rel entry_name]
    call find_entry
    test rax, rax
    jnz err_entry_exists

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

    ; Show password strength
    lea rdi, [rel entry_pass]
    call print_strength

    ; Zero sensitive data
    call zero_sensitive

    lea rdi, [rel msg_added]
    call print_str
    xor edi, edi
    call exit

; ── vault get <name> [field] ─────────────────────────────────
do_get:
    mov rax, [rel argc]
    cmp rax, 3
    jl err_need_name

    mov rax, [rel argv]
    mov rsi, [rax+16]       ; argv[2] = source
    lea rdi, [rel entry_name]
    call strcpy

    call open_vault

    ; Find entry (fuzzy)
    lea rdi, [rel entry_name]
    call find_entry_fuzzy
    test rax, rax
    jz err_not_found

    ; rax = pointer to entry in vault_buf
    ; Decrypt it
    mov rsi, rax
    call decrypt_entry      ; entry_user/pass/url/notes filled

    ; Check if field specified (argc >= 4)
    mov rax, [rel argc]
    cmp rax, 4
    jl .get_all

    ; Get field name from argv[3]
    mov rax, [rel argv]
    mov rdi, [rax+24]       ; argv[3]

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
    lea rdi, [rel entry_user]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_pass:
    lea rdi, [rel entry_pass]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_url:
    lea rdi, [rel entry_url]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_notes:
    lea rdi, [rel entry_notes]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_totp:
    lea rdi, [rel entry_totp]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str
    jmp .get_done

.get_all:
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
    call print_str
    xor edi, edi
    call exit

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

    call read_vault_file
    test rax, rax
    jz err_no_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    test eax, eax
    jz err_list_empty

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

; ── vault count — show total entries ─────────────────────────
do_count:
    call read_vault_file
    test rax, rax
    jz err_no_vault

    lea rsi, [rel vault_buf]
    mov eax, [rsi + 62]
    lea rdi, [rel numbuf]
    call itoa
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_entries]
    call print_str

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
    lea rdi, [rel msg_no_xclip]
    call print_str
    mov edi, 1
    call exit

; ════════════════════════════════════════════════════════════════
; L3 Commands
; ════════════════════════════════════════════════════════════════

; ── vault verify — check vault integrity ─────────────────────
do_verify:
    call open_vault
    ; If we get here, HMAC was verified successfully
    call zero_sensitive
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
    push rdx                ; save TOTP code
    lea rdi, [rel msg_totp_code]
    call print_str
    pop rdx

    mov eax, edx
    lea rdi, [rel numbuf]
    call itoa_padded6
    lea rdi, [rel numbuf]
    call print_str
    lea rdi, [rel msg_newline]
    call print_str

    call zero_sensitive
    xor edi, edi
    call exit

.totp_no_secret:
    call zero_sensitive
    lea rdi, [rel msg_totp_none]
    call print_str
    lea rdi, [rel msg_totp_hint]
    call print_str
    mov edi, 1
    call exit

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

; ── vault unlock — cache derived key for session ─────────────
do_unlock:
    ; Build session path
    call build_session_path

    ; Open vault normally (prompts for password)
    call open_vault

    ; Generate a session encryption key from random data
    ; We store the derived_key XOR'd with a random nonce
    ; Session file format: random_nonce(16) + XOR'd_key(32) = 48 bytes
    lea rdi, [rel session_buf]
    mov esi, 16
    call get_random          ; 16-byte nonce

    ; XOR derived_key with SHA-256(nonce) to create stored form
    lea rdi, [rel session_buf]
    mov esi, 16
    lea rdx, [rel hidden_salt]  ; reuse as temp hash output
    call sha256_hash

    ; Copy derived key then XOR with hash
    lea rdi, [rel session_buf]
    add rdi, 16
    lea rsi, [rel derived_key]
    mov ecx, 32
    rep movsb
    ; XOR
    lea rdi, [rel session_buf]
    add rdi, 16
    lea rsi, [rel hidden_salt]
    mov ecx, 32
.unlock_xor:
    mov al, [rsi]
    xor [rdi], al
    inc rdi
    inc rsi
    dec ecx
    jnz .unlock_xor

    ; Write session file (mode 0600)
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, 48
    mov ecx, 0o600
    call write_file

    ; Fork a background timer to auto-delete after timeout
    mov eax, SYS_FORK
    syscall
    test eax, eax
    jnz .unlock_parent

    ; Child: become session leader, sleep, then wipe session file
    mov eax, SYS_SETSID
    syscall

    sub rsp, 16
    mov qword [rsp], SESSION_TIMEOUT
    mov qword [rsp+8], 0
    mov rdi, rsp
    xor esi, esi
    mov eax, SYS_NANOSLEEP
    syscall
    add rsp, 16

    ; Wipe session file
    call wipe_session_file
    xor edi, edi
    call exit

.unlock_parent:
    call zero_sensitive
    ; Zero session_buf
    lea rdi, [rel session_buf]
    mov ecx, 64
    call zero_mem

    lea rdi, [rel msg_unlocked]
    call print_str
    xor edi, edi
    call exit

; ── vault lock — clear session ───────────────────────────────
do_lock:
    call build_session_path
    lea rdi, [rel session_path]
    call file_exists
    test eax, eax
    jz .lock_no_session

    call wipe_session_file

    lea rdi, [rel msg_locked]
    call print_str
    xor edi, edi
    call exit

.lock_no_session:
    lea rdi, [rel msg_no_session]
    call print_str
    xor edi, edi
    call exit

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

do_hidden:
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
    lea rdi, [rel msg_mismatch]
    call print_str
    mov edi, 1
    call exit

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
    call ctr_crypt

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
    pop rbx
    ret

; wipe_session_file — securely wipe and delete session file
wipe_session_file:
    ; Overwrite with zeros
    lea rdi, [rel session_buf]
    mov ecx, 64
    xor al, al
    rep stosb
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, 48
    mov ecx, 0o600
    call write_file
    ; Delete
    lea rdi, [rel session_path]
    mov eax, SYS_UNLINK
    syscall
    ret

; try_load_session — check for session file and load cached key
;   Returns: eax = 1 if session loaded (derived_key set), 0 if not
try_load_session:
    push rbx
    call build_session_path
    lea rdi, [rel session_path]
    call file_exists
    test eax, eax
    jz .tls_no

    ; Read session file
    lea rdi, [rel session_path]
    lea rsi, [rel session_buf]
    mov edx, 48
    call read_file
    cmp eax, 48
    jne .tls_no

    ; Decrypt: key = stored_key XOR SHA-256(nonce)
    lea rdi, [rel session_buf]
    mov esi, 16
    lea rdx, [rel hidden_salt]  ; reuse as temp
    call sha256_hash

    ; Copy encrypted key and XOR with hash
    lea rsi, [rel session_buf]
    add rsi, 16
    lea rdi, [rel derived_key]
    mov ecx, 32
    rep movsb
    lea rdi, [rel derived_key]
    lea rsi, [rel hidden_salt]
    mov ecx, 32
.tls_xor:
    mov al, [rsi]
    xor [rdi], al
    inc rdi
    inc rsi
    dec ecx
    jnz .tls_xor

    ; Zero session_buf
    lea rdi, [rel session_buf]
    mov ecx, 64
    call zero_mem

    mov eax, 1
    pop rbx
    ret

.tls_no:
    xor eax, eax
    pop rbx
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

    ; Compare with stored HMAC (32 bytes before entry count)
    lea rdi, [rel hidden_hmac]
    mov rsi, [rel hidden_section_ptr]
    sub rsi, 32
    mov ecx, 32
    call memcmp
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
    lea rdi, [rel msg_no_vault]
    call print_str
    mov edi, 1
    call exit

.ohv_hmac_fail:
    lea rdi, [rel msg_hmac_fail]
    call print_str
    mov edi, 1
    call exit

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
    call ctr_crypt

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

    ; Read keyfile
    mov rdi, [rel keyfile_path]
    lea rsi, [rel keyfile_buf]
    mov edx, 256
    call read_file
    test eax, eax
    jz .akf_done            ; skip if file empty/missing

    ; Hash keyfile contents: SHA-256(keyfile_data)
    lea rdi, [rel keyfile_buf]
    mov esi, eax
    lea rdx, [rel keyfile_hash]
    call sha256_hash

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
    ; Zero keyfile buffer
    lea rdi, [rel keyfile_buf]
    mov ecx, 256
    call zero_mem

    pop rcx
    pop rbx
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

    ; Check for active session first
    call try_load_session
    test eax, eax
    jnz .ov_session_loaded

    ; No session — read master password
    lea rdi, [rel prompt_master]
    lea rsi, [rel master_pw]
    mov edx, 255
    call read_password
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

    ; PBKDF2-SHA256
    lea rdi, [rel master_pw]
    mov rsi, r12
    lea rdx, [rel vault_salt]
    mov ecx, SALT_LEN
    mov r8, PBKDF2_ITER
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
    ; Verify HMAC
    ; Stored HMAC is at offset 30 (8+2+16+4)
    ; Data to verify starts at offset 62 (30+32)
    mov rax, [rel vault_file_size]
    sub rax, 62             ; data length
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256

    ; Compare with stored HMAC
    lea rdi, [rel vault_hmac]
    lea rsi, [rel vault_buf]
    add rsi, 30
    mov ecx, 32
    call memcmp
    test eax, eax
    jnz .hmac_fail

    pop r15
    pop r12
    ret

.no_vault_helper:
    lea rdi, [rel msg_no_vault]
    call print_str
    mov edi, 1
    call exit

.hmac_fail:
    call zero_sensitive
    lea rdi, [rel msg_hmac_fail]
    call print_str
    mov edi, 1
    call exit

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

    ; Compare name
    mov eax, [rsi]          ; name_len
    add rsi, 4              ; name data
    mov rdi, r12
    call strlen
    cmp eax, [rsp]          ; compare lengths... wait, name_len is at [rsp] entry start
    ; Let me redo: rsi = name_data, eax = name_len from header
    mov edx, eax            ; name_len
    push rdx
    mov rdi, r12
    mov rcx, rdx
    call memcmp_n           ; compare rcx bytes of rdi vs rsi
    pop rdx
    test eax, eax
    jnz .fe_next

    ; Also check that the search name length matches
    mov rdi, r12
    call strlen
    cmp eax, edx
    jne .fe_next

    ; Found! Return pointer to entry start
    pop rax                 ; entry start
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

    ; HMAC over data from offset 62 to end
    mov rax, rdx
    sub rax, 62             ; data length
    lea rdi, [rel derived_key]
    mov rsi, 32
    lea rdx, [rel vault_buf]
    add rdx, 62
    mov rcx, rax
    lea r8, [rel vault_hmac]
    call hmac_sha256

    ; Copy HMAC to header at offset 30
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
    call print_str

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

    ; Print newline (since echo was off)
    lea rdi, [rel msg_newline]
    call print_str

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
    mov r12, rsi            ; buffer
    mov r13d, edx           ; max size

    mov esi, O_RDONLY
    mov eax, SYS_OPEN
    syscall
    test eax, eax
    js .rf_err

    mov edi, eax            ; fd
    push rdi
    mov rsi, r12
    mov edx, r13d
    mov eax, SYS_READ
    syscall
    push rax                ; bytes read
    pop rax
    pop rdi
    push rax
    mov eax, SYS_CLOSE
    syscall
    pop rax

    pop r13
    pop r12
    ret
.rf_err:
    xor eax, eax
    pop r13
    pop r12
    ret

; write_file — write buffer to file
;   rdi = path, rsi = data, edx = length, ecx = mode
write_file:
    push r12
    push r13
    push r14
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
    push rdi
    mov rsi, r12
    mov edx, r13d
    mov eax, SYS_WRITE
    syscall
    pop rdi
    mov eax, SYS_CLOSE
    syscall

.wf_err:
    pop r14
    pop r13
    pop r12
    ret

; get_random — fill buffer with random bytes
;   rdi = buffer, esi = count
get_random:
    mov edx, 0              ; flags
    mov eax, SYS_GETRANDOM
    syscall
    ret

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
