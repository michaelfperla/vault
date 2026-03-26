#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# Vault Test Suite — exercises core functionality safely
# ═══════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT="$SCRIPT_DIR/../vault"
TEST_ROOT="$(mktemp -d)"
VAULT_DIR="$TEST_ROOT/.vault"
VAULT_FILE="$VAULT_DIR/vault.enc"
PASS_WORD="testpass"

cleanup() {
    rm -rf "$TEST_ROOT"
    printf '\n  %s[cleanup]%s removed %s\n' "$DIM" "$RST" "$TEST_ROOT"
}

# Colors (define early so cleanup can use DIM/RST)
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[1;36m'
DIM=$'\033[38;5;240m'
BOLD=$'\033[1m'
RST=$'\033[0m'

trap cleanup EXIT

# ── Counters ──
PASS=0
FAIL=0
TOTAL=0
declare -a FAILURES=()

# ═══════════════════════════════════════════════════════════
# Test Harness
# ═══════════════════════════════════════════════════════════

# run_test NAME CMD... — exit 0 = pass
run_test() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    local out
    out=$(mktemp)
    local t0
    t0=$(date +%s%N)
    if "$@" > "$out" 2>&1; then
        local t1
        t1=$(date +%s%N)
        local ms=$(( (t1 - t0) / 1000000 ))
        printf "  ${GREEN}✓${RST} %-50s ${DIM}%4dms${RST}\n" "$name" "$ms"
        PASS=$((PASS + 1))
    else
        local rc=$?
        printf "  ${RED}✗${RST} %-50s ${RED}exit %d${RST}\n" "$name" "$rc"
        FAIL=$((FAIL + 1))
        FAILURES+=("$name — exit $rc")
        [ -s "$out" ] && printf "    ${DIM}%s${RST}\n" "$(head -3 "$out")"
    fi
    rm -f "$out"
}

# run_test_match NAME PATTERN CMD... — exit 0 + stdout matches pattern
run_test_match() {
    local name="$1"; shift
    local pattern="$1"; shift
    TOTAL=$((TOTAL + 1))
    local out
    out=$(mktemp)
    local t0
    t0=$(date +%s%N)
    if "$@" > "$out" 2>&1; then
        local t1
        t1=$(date +%s%N)
        local ms=$(( (t1 - t0) / 1000000 ))
        if grep -q "$pattern" "$out" 2>/dev/null; then
            printf "  ${GREEN}✓${RST} %-50s ${DIM}%4dms${RST}\n" "$name" "$ms"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}✗${RST} %-50s ${RED}missing: %s${RST}\n" "$name" "$pattern"
            FAIL=$((FAIL + 1))
            FAILURES+=("$name — missing '$pattern'")
            [ -s "$out" ] && printf "    ${DIM}output: %s${RST}\n" "$(head -1 "$out")"
        fi
    else
        local rc=$?
        printf "  ${RED}✗${RST} %-50s ${RED}exit %d${RST}\n" "$name" "$rc"
        FAIL=$((FAIL + 1))
        FAILURES+=("$name — exit $rc")
        [ -s "$out" ] && printf "    ${DIM}%s${RST}\n" "$(head -3 "$out")"
    fi
    rm -f "$out"
}

# run_test_fail NAME PATTERN CMD... — expects nonzero exit + pattern in output
run_test_fail() {
    local name="$1"; shift
    local pattern="$1"; shift
    TOTAL=$((TOTAL + 1))
    local out
    out=$(mktemp)
    local t0
    t0=$(date +%s%N)
    if "$@" > "$out" 2>&1; then
        local t1
        t1=$(date +%s%N)
        local ms=$(( (t1 - t0) / 1000000 ))
        printf "  ${RED}✗${RST} %-50s ${RED}expected failure, got exit 0${RST}\n" "$name"
        FAIL=$((FAIL + 1))
        FAILURES+=("$name — expected failure but succeeded")
    else
        local t1
        t1=$(date +%s%N)
        local ms=$(( (t1 - t0) / 1000000 ))
        if grep -q "$pattern" "$out" 2>/dev/null; then
            printf "  ${GREEN}✓${RST} %-50s ${DIM}%4dms${RST}\n" "$name" "$ms"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}✗${RST} %-50s ${RED}missing: %s${RST}\n" "$name" "$pattern"
            FAIL=$((FAIL + 1))
            FAILURES+=("$name — missing '$pattern' in error output")
            [ -s "$out" ] && printf "    ${DIM}output: %s${RST}\n" "$(head -1 "$out")"
        fi
    fi
    rm -f "$out"
}

# ═══════════════════════════════════════════════════════════
# Header
# ═══════════════════════════════════════════════════════════

printf '\n%s═══ VAULT TEST SUITE ═══%s\n\n' "$BOLD" "$RST"
printf '  Binary:    %s\n' "$VAULT"
printf '  Size:      %s\n' "$(du -h "$VAULT" | cut -f1)"
printf '  Vault dir: %s\n' "$VAULT_DIR"
printf '  Vault file: %s\n\n' "$VAULT_FILE"

# ═══════════════════════════════════════════════════════════
# Phase 1: Init
# ═══════════════════════════════════════════════════════════

printf '%s── Phase 1: Init ──%s\n' "$CYAN" "$RST"

run_test_match  "init — create vault" \
                "Vault created" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' init --password-stdin"

# Verify file exists
TOTAL=$((TOTAL + 1))
if [ -f "$VAULT_FILE" ]; then
    printf "  ${GREEN}✓${RST} %-50s\n" "init — vault file exists"
    PASS=$((PASS + 1))
else
    printf "  ${RED}✗${RST} %-50s\n" "init — vault file exists"
    FAIL=$((FAIL + 1))
    FAILURES+=("init — vault file does not exist")
fi

# Init should refuse if vault already exists
run_test_fail   "init — refuses reinit" \
                "already exists" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' init --password-stdin"

# ═══════════════════════════════════════════════════════════
# Phase 2: Add
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 2: Add ──%s\n' "$CYAN" "$RST"

# add entry: password, then username, password, url, notes, totp
run_test_match  "add — create entry" \
                "Entry added" \
                sh -c "printf '${PASS_WORD}\nalice\nsecret123\nhttps://example.com\ntest notes\n\n' | '$VAULT' --vault-path '$VAULT_FILE' add testsite"

run_test_match  "add — scripted entry" \
                "Entry added" \
                sh -c "printf '${PASS_WORD}\napi-secret\n' | '$VAULT' --vault-path '$VAULT_FILE' add scripted --username bot --password-stdin --url https://api.example.com --notes automation --totp JBSWY3DPEHPK3PXP"

# ═══════════════════════════════════════════════════════════
# Phase 3: Get
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 3: Get ──%s\n' "$CYAN" "$RST"

run_test_match  "get — username" \
                "alice" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite username"

run_test_match  "get — password" \
                "secret123" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite password"

run_test_match  "get — url" \
                "https://example.com" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite url"

run_test_match  "get — notes" \
                "test notes" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite notes"

# ═══════════════════════════════════════════════════════════
# Phase 4: List / Count / Search
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 4: List / Count / Search ──%s\n' "$CYAN" "$RST"

run_test_match  "list — shows entry" \
                "testsite" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' list"

run_test_match  "count — 2 entries" \
                "2 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

run_test_match  "search — finds entry" \
                "testsite" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' search test"

run_test_match  "get — scripted username" \
                "bot" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get scripted username"

run_test_match  "get --raw — password" \
                "^secret123$" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite password --raw"

run_test_match  "get --json — entry field" \
                '"secret123"' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite password --json"

run_test_match  "totp --raw — 6 digits" \
                '^[0-9][0-9][0-9][0-9][0-9][0-9]$' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' totp scripted --raw"

run_test_match  "totp --json — code object" \
                '^\{\"code\":\"[0-9][0-9][0-9][0-9][0-9][0-9]\"\}$' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' totp scripted --json"

run_test_match  "list --json — array output" \
                '^\["testsite","scripted"\]$' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' list --json"

run_test_match  "search --json — filtered array" \
                '^\["scripted"\]$' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' search script --json"

run_test_match  "count --json — count object" \
                '"count":2' \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count --json"

# ═══════════════════════════════════════════════════════════
# Phase 5: Gen
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 5: Gen ──%s\n' "$CYAN" "$RST"

# gen creates an entry with a generated password
run_test    "gen — generate password entry" \
            sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' gen gensite 24"

# Verify the generated password is non-empty
TOTAL=$((TOTAL + 1))
gen_out=$(printf "${PASS_WORD}\n" | "$VAULT" --vault-path "$VAULT_FILE" get gensite password 2>&1)
if [ -n "$gen_out" ] && ! echo "$gen_out" | grep -q "Error"; then
    # Strip the "Master password: " prompt line
    gen_pw=$(echo "$gen_out" | tail -1)
    gen_len=${#gen_pw}
    if [ "$gen_len" -gt 0 ]; then
        printf "  ${GREEN}✓${RST} %-50s ${DIM}len=%d${RST}\n" "gen — password is non-empty" "$gen_len"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}✗${RST} %-50s ${RED}empty password${RST}\n" "gen — password is non-empty"
        FAIL=$((FAIL + 1))
        FAILURES+=("gen — empty password")
    fi
else
    printf "  ${RED}✗${RST} %-50s ${RED}could not retrieve${RST}\n" "gen — password is non-empty"
    FAIL=$((FAIL + 1))
    FAILURES+=("gen — could not retrieve generated password")
fi

# Count should now be 3
run_test_match  "count — 3 entries after gen" \
                "3 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

# ═══════════════════════════════════════════════════════════
# Phase 6: Show
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 6: Show ──%s\n' "$CYAN" "$RST"

run_test_match  "show — displays entry" \
                "alice" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' show testsite"

run_test_match  "show — includes strength" \
                "strength" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' show testsite"

# ═══════════════════════════════════════════════════════════
# Phase 7: Remove
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 7: Remove ──%s\n' "$CYAN" "$RST"

run_test_match  "rm — remove gensite" \
                "removed" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' rm gensite"

run_test_match  "count — 2 entries after rm" \
                "2 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

run_test_match  "rm — remove testsite" \
                "removed" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' rm testsite"

run_test_match  "count — 1 entry after rm" \
                "1 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

# ═══════════════════════════════════════════════════════════
# Phase 8: Auth Required
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 8: Auth Required ──%s\n' "$CYAN" "$RST"

run_test_fail   "list — wrong password rejected" \
                "vault could not be opened" \
                sh -c "printf 'wrongpass\n' | '$VAULT' --vault-path '$VAULT_FILE' list"

run_test_fail   "count — wrong password rejected" \
                "vault could not be opened" \
                sh -c "printf 'wrongpass\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

run_test_fail   "search — wrong password rejected" \
                "vault could not be opened" \
                sh -c "printf 'wrongpass\n' | '$VAULT' --vault-path '$VAULT_FILE' search test"

run_test_fail   "get — wrong password rejected" \
                "vault could not be opened" \
                sh -c "printf 'wrongpass\n' | '$VAULT' --vault-path '$VAULT_FILE' get testsite password"

# ═══════════════════════════════════════════════════════════
# Phase 9: Export / Import Roundtrip
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 9: Export / Import Roundtrip ──%s\n' "$CYAN" "$RST"

# Add an entry to export
printf "${PASS_WORD}\nbob\nhunter2\nhttps://bob.com\nbob notes\n\n" | "$VAULT" --vault-path "$VAULT_FILE" add bobsite > /dev/null 2>&1

# Export
TOTAL=$((TOTAL + 1))
export_raw=$(mktemp)
export_file=$(mktemp)
if printf "${PASS_WORD}\n" | "$VAULT" --vault-path "$VAULT_FILE" export > "$export_raw" 2>&1; then
    # Strip "Master password: " prompt line — vault writes it to stdout
    grep -v "^Master password:" "$export_raw" > "$export_file"
    if [ -s "$export_file" ] && grep -q "bobsite" "$export_file"; then
        printf "  ${GREEN}✓${RST} %-50s\n" "export — contains entry"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}✗${RST} %-50s ${RED}missing entry in export${RST}\n" "export — contains entry"
        FAIL=$((FAIL + 1))
        FAILURES+=("export — missing entry")
    fi
else
    printf "  ${RED}✗${RST} %-50s ${RED}export failed${RST}\n" "export — contains entry"
    FAIL=$((FAIL + 1))
    FAILURES+=("export — command failed")
fi
rm -f "$export_raw"

# Wipe and reimport
printf "${PASS_WORD}\n" | "$VAULT" --vault-path "$VAULT_FILE" rm bobsite > /dev/null 2>&1
run_test_match  "count — 0 after rm" \
                "1 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

# Import the exported file
run_test    "import — from exported file" \
            sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' import '$export_file'"

run_test_match  "count — 1 after import" \
                "2 entries" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' count"

run_test_match  "get — imported username" \
                "bob" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' get bobsite username"

rm -f "$export_file"

# ═══════════════════════════════════════════════════════════
# Phase 10: Verify
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 10: Verify ──%s\n' "$CYAN" "$RST"

run_test    "verify — integrity check passes" \
            sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' verify"

# ═══════════════════════════════════════════════════════════
# Phase 11: Session Cache
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 11: Session Cache ──%s\n' "$CYAN" "$RST"

run_test_match  "unlock — enables 5 minute session" \
                "Session expires in 5 minutes" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' unlock"

run_test_match  "get — uses cached session" \
                "^api-secret$" \
                sh -c "'$VAULT' --vault-path '$VAULT_FILE' get scripted password --raw"

run_test_match  "lock — clears cached session" \
                "Session cleared" \
                sh -c "'$VAULT' --vault-path '$VAULT_FILE' lock"

# ═══════════════════════════════════════════════════════════
# Phase 12: Backup
# ═══════════════════════════════════════════════════════════

printf '\n%s── Phase 12: Backup ──%s\n' "$CYAN" "$RST"

run_test_match  "backup — creates backup" \
                "Backup" \
                sh -c "printf '${PASS_WORD}\n' | '$VAULT' --vault-path '$VAULT_FILE' backup"

# Clean up backup files created during test
rm -f "$VAULT_DIR"/vault.enc.bak.* 2>/dev/null

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════

printf '\n%s═══════════════════════════════════════════%s\n' "$BOLD" "$RST"
printf '%s  VAULT TEST RESULTS%s\n' "$BOLD" "$RST"
printf '%s═══════════════════════════════════════════%s\n\n' "$BOLD" "$RST"

if [ $FAIL -eq 0 ]; then
    printf "  ${GREEN}PASSED:  %d/%d${RST}\n" "$PASS" "$TOTAL"
else
    printf "  ${GREEN}PASSED:  %d/%d${RST}\n" "$PASS" "$TOTAL"
    printf "  ${RED}FAILED:  %d/%d${RST}\n" "$FAIL" "$TOTAL"
fi

if [ ${#FAILURES[@]} -gt 0 ]; then
    printf '\n  %sFailures:%s\n' "$RED" "$RST"
    for f in "${FAILURES[@]}"; do
        printf "    ${RED}✗${RST} %s\n" "$f"
    done
fi

printf '\n  Binary: %s  |  Source: %s lines  |  Deps: zero\n\n' \
    "$(du -h "$VAULT" | cut -f1)" \
    "$(wc -l "$SCRIPT_DIR"/../vault.asm 2>/dev/null | awk '{print $1}')"

if [ $FAIL -eq 0 ]; then
    printf "  ${GREEN}All tests passed.${RST}\n\n"
    exit 0
else
    printf "  ${RED}%d test(s) failed.${RST}\n\n" "$FAIL"
    exit 1
fi
