#!/usr/bin/env bash
# Test suite for easypki.sh
# Many scenarios: happy paths, edge cases, error paths, multiple PKI dirs, etc.

set -u -o pipefail
export LC_ALL=C

# === CONFIG ===
EASYPKI="${EASYPKI:-./easypki.sh}"

# === COLORS (test local) ===
_test_colors() {
  if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
    local n; n=$(tput colors 2>/dev/null || echo 0)
    if (( n >= 8 )); then
      T_BOLD="$(tput bold)"
      T_RESET="$(tput sgr0)"
      T_CYAN="$(tput setaf 6)"
      T_YELLOW="$(tput setaf 3)"
      T_GREEN="$(tput setaf 2)"
      T_RED="$(tput setaf 1)"
      return
    fi
  fi
  T_BOLD=""; T_RESET=""; T_CYAN=""; T_YELLOW=""; T_GREEN=""; T_RED=""
}

_test_colors

# === SIMPLE LOGGING FOR TESTS ===
tlog(){ printf '%s[*]%s %s\n' "$T_CYAN"  "$T_RESET" "$*"; }
tok(){  printf '%s[OK]%s %s\n' "$T_GREEN" "$T_RESET" "$*"; }
tko(){  printf '%s[FAIL]%s %s\n' "$T_RED"  "$T_RESET" "$*"; }

TESTS_RUN=0
TESTS_OK=0

# run_ok "description" cmd...
run_ok() {
  local desc="$1"; shift
  TESTS_RUN=$((TESTS_RUN+1))
  tlog "TEST (expect success): $desc"
  if "$@" >"$BASE_DIR/log.out" 2>"$BASE_DIR/log.err"; then
    TESTS_OK=$((TESTS_OK+1))
    tok "$desc"
  else
    tko "$desc"
    echo "  ${T_YELLOW}-> command failed with exit code $?${T_RESET}"
    echo "  STDOUT:"
    sed 's/^/    /' "$BASE_DIR/log.out" || true
    echo "  STDERR:"
    sed 's/^/    /' "$BASE_DIR/log.err" || true
  fi
}

# run_fail "description" cmd...
run_fail() {
  local desc="$1"; shift
  TESTS_RUN=$((TESTS_RUN+1))
  tlog "TEST (expect failure): $desc"
  if "$@" >"$BASE_DIR/log.out" 2>"$BASE_DIR/log.err"; then
    tko "$desc"
    echo "  ${T_YELLOW}-> command unexpectedly succeeded${T_RESET}"
    echo "  STDOUT:"
    sed 's/^/    /' "$BASE_DIR/log.out" || true
    echo "  STDERR:"
    sed 's/^/    /' "$BASE_DIR/log.err" || true
  else
    TESTS_OK=$((TESTS_OK+1))
    tok "$desc"
  fi
}

# small helper: require file/dir existence
assert_file() {
  local f="$1" msg="$2"
  TESTS_RUN=$((TESTS_RUN+1))
  tlog "ASSERT FILE: $msg"
  if [[ -f "$f" ]]; then
    TESTS_OK=$((TESTS_OK+1))
    tok "$msg"
  else
    tko "$msg"
    echo "  ${T_YELLOW}-> missing file: $f${T_RESET}"
  fi
}

assert_dir() {
  local d="$1" msg="$2"
  TESTS_RUN=$((TESTS_RUN+1))
  tlog "ASSERT DIR: $msg"
  if [[ -d "$d" ]]; then
    TESTS_OK=$((TESTS_OK+1))
    tok "$msg"
  else
    tko "$msg"
    echo "  ${T_YELLOW}-> missing dir: $d${T_RESET}"
  fi
}

# === PRECHECKS ===
if [[ ! -x "$EASYPKI" ]]; then
  echo "${T_RED}[FATAL]${T_RESET} easypki.sh not found or not executable at: $EASYPKI" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "${T_RED}[FATAL]${T_RESET} openssl not found in PATH" >&2
  exit 1
fi

# === WORKSPACE ===
BASE_DIR="${BASE_DIR:-$(mktemp -d -t easypki-tests.XXXXXX)}"
echo "${T_CYAN}[*]${T_RESET} Using test workspace: ${T_BOLD}$BASE_DIR${T_RESET}"
echo "${T_CYAN}[*]${T_RESET} easypki binary: ${T_BOLD}$EASYPKI${T_RESET}"
echo "${T_CYAN}[*]${T_RESET} Root key passphrase prompts are ${T_YELLOW}DISABLED${T_RESET} in tests via ${T_BOLD}EASYPKI_INSECURE_NO_PASSPHRASE=1${T_RESET}"
echo

# Separate PKI dirs for different scenarios
PKI_MAIN="$BASE_DIR/pki-main"       # main big PKI
PKI_ALT="$BASE_DIR/pki-alt"         # alternate PKI
PKI_BROKEN="$BASE_DIR/pki-broken"   # intentionally broken

mkdir -p "$PKI_MAIN" "$PKI_ALT" "$PKI_BROKEN"

# When creating Root in tests, we want unencrypted key:
export EASYPKI_INSECURE_NO_PASSPHRASE=1

########################################
# 1. Generic / CLI sanity
########################################

run_fail  "No subcommand should fail / show help" \
  "$EASYPKI"

run_fail  "Unknown subcommand should fail" \
  "$EASYPKI" foo

run_ok    "Global help with --help" \
  "$EASYPKI" --help

########################################
# 2. ROOT: errors, creation, idempotency, json
########################################

run_ok  "root --info on empty PKI_MAIN dir" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --info

run_fail "root with invalid --root-days" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --root-days not_a_number

run_fail "root with invalid --crl-days-root" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --crl-days-root abc

run_fail "root with crl-days-root > root-days" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --root-days 365 --crl-days-root 366

run_ok   "Create Root CA in PKI_MAIN (unencrypted key test mode)" \
  "$EASYPKI" root \
    --pki-dir "$PKI_MAIN" \
    --country FR \
    --state "Ile-de-France" \
    --locality "Paris" \
    --org "Homelab" \
    --root-cn "Homelab Root CA"

assert_dir  "$PKI_MAIN/root"               "Root directory created"
assert_file "$PKI_MAIN/root/private/ca.key.pem" "Root private key exists"
assert_file "$PKI_MAIN/root/certs/ca.cert.pem"  "Root certificate exists"
assert_file "$PKI_MAIN/root/crl/root.crl"       "Root CRL exists"

run_ok   "Root CA creation is idempotent" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN"

run_ok   "Root --info on existing Root" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --info

run_ok   "Root --renew-crl" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --renew-crl

# JSON output test
run_ok   "Root --json output" \
  "$EASYPKI" root --pki-dir "$PKI_MAIN" --json

ROOT_JSON_CERT_PATH="$(grep -o '"cert":"[^"]*"' "$BASE_DIR/log.out" | head -n1 | sed 's/.*:"//;s/"$//')"
if [[ -n "${ROOT_JSON_CERT_PATH:-}" ]]; then
  assert_file "$ROOT_JSON_CERT_PATH" "Root --json cert path exists"
fi

########################################
# 3. ROOT in alternate PKI + slightly different DN
########################################

run_ok   "Create Root CA in PKI_ALT with different DN" \
  "$EASYPKI" root \
    --pki-dir "$PKI_ALT" \
    --country DE \
    --state "Berlin" \
    --locality "Berlin" \
    --org "Homelab Alt" \
    --root-cn "Homelab Alt Root CA"

assert_file "$PKI_ALT/root/certs/ca.cert.pem" "Alt Root certificate exists"

########################################
# 4. INTERMEDIATES: errors and sanity
########################################

run_fail "int without options should fail" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN"

run_fail "int with invalid intermediate name (spaces)" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" -i "bad name"

run_fail "int with invalid numeric int-days" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" -i apps --int-days nope

run_fail "int with crl-days-int > int-days" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" -i apps --int-days 10 --crl-days-int 11

# revoke-intermediate without root
run_fail "int --revoke-intermediate on PKI_BROKEN (no root)" \
  "$EASYPKI" int --pki-dir "$PKI_BROKEN" --revoke-intermediate apps

########################################
# 5. INTERMEDIATES: massive creation
########################################

run_ok   "Create intermediates apps, users, vpn, infra" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" \
    -i apps \
    -i users \
    -i vpn \
    -i infra \
    --country FR \
    --state "Ile-de-France" \
    --locality "Paris" \
    --org "Homelab" \
    --int-cn-prefix "Homelab Intermediate - "

for ca in apps users vpn infra; do
  assert_dir  "$PKI_MAIN/intermediates/$ca"                     "Intermediate dir $ca exists"
  assert_file "$PKI_MAIN/intermediates/$ca/certs/intermediate.cert.pem" "Intermediate $ca cert exists"
  assert_file "$PKI_MAIN/chain/$ca.chain.pem"                   "Intermediate $ca chain exists"
done

run_ok   "int --info on all intermediates" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" --info

########################################
# 6. CERT: generic error cases
########################################

run_fail "cert without action should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN"

run_fail "cert --issue-user with no --ca should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --issue-user alice

run_fail "cert --issue-user with invalid NAME (spaces)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-user "bad name"

run_fail "cert --issue-user with invalid --days" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-user alice --days not_a_number

run_ok   "cert --list on PKI_MAIN (no certs yet)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --list

run_ok   "cert --list on PKI_ALT (no intermediates but should not crash)" \
  "$EASYPKI" cert --pki-dir "$PKI_ALT" --list

########################################
# 7. CERT: issue multiple user certs
########################################

USERS=(alice bob carol dave eve mallory)
for u in "${USERS[@]}"; do
  run_ok "Issue user cert '$u' under CA 'apps'" \
    "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-user "$u" --days 365
  assert_dir  "$PKI_MAIN/intermediates/apps/issued/$u"                  "Issued dir for $u exists"
  assert_file "$PKI_MAIN/intermediates/apps/issued/$u/$u.cert.pem"      "Cert file for $u exists"
  assert_file "$PKI_MAIN/intermediates/apps/issued/$u/$u.fullchain.pem" "Fullchain for $u exists"
done

run_ok "cert --list after user cert issuance" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --list

########################################
# 8. CERT: server certs with funky SANs
########################################

run_ok   "Issue simple server cert without SAN under CA 'users'" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --issue-server api.homelab.lan

run_ok   "Issue server cert with SAN via multiple --san entries" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --issue-server web.homelab.lan \
    --days 825 \
    --san "DNS:web.homelab.lan,IP:10.0.0.10" \
    --san "DNS:web.homelab.lan" \
    --san "IP:10.0.0.10"

run_ok   "Issue server cert with bare SAN (normalized to DNS:)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --issue-server bare-san.homelab.lan \
    --san "bare-san.homelab.lan"

run_ok   "Issue server cert with mixed SAN values & duplicates" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca vpn --issue-server vpn.homelab.lan \
    --san "DNS:vpn.homelab.lan,IP:10.0.0.20" \
    --san "vpn.homelab.lan" \
    --san "DNS:vpn.homelab.lan,IP:10.0.0.20"

########################################
# 9. CERT: replace logic (user + server)
########################################

run_ok   "Issue server cert replace-test.homelab.lan (apps CA)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-server replace-test.homelab.lan

run_fail "Re-issue server cert without --replace should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-server replace-test.homelab.lan

run_ok   "Re-issue server cert with --replace should succeed" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-server replace-test.homelab.lan --replace

run_ok   "Issue user cert 'frank' (apps)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-user frank

run_ok   "Re-issue user cert 'frank' with --replace" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --issue-user frank --replace

########################################
# 10. CERT: info & SAN check & chain verify
########################################

run_ok "cert --info on user 'alice'" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --info alice

run_ok "cert --info on server web.homelab.lan (with SANs)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --info web.homelab.lan

run_fail "cert --info on unknown subject" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --info unknown-subject

# basic external chain verify: pick one cert and its chain
APP_CHAIN="$PKI_MAIN/chain/apps.chain.pem"
ALICE_CERT="$PKI_MAIN/intermediates/apps/issued/alice/alice.cert.pem"

if [[ -f "$APP_CHAIN" && -f "$ALICE_CERT" ]]; then
  run_ok "openssl verify external: alice.cert.pem against apps.chain.pem" \
    openssl verify -CAfile "$APP_CHAIN" "$ALICE_CERT"
fi

########################################
# 11. CERT: revoke end-entity certs & double revoke
########################################

run_ok   "Revoke user cert 'bob' (apps)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --revoke bob

run_ok   "Revoke server cert 'api.homelab.lan' (users)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --revoke api.homelab.lan

run_ok   "cert --list after some revocations" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --list

run_fail "Revoke already revoked cert 'bob' should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --revoke bob

########################################
# 12. CERT: CRL generation
########################################

run_ok   "Generate CRL for specific CA 'apps'" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca apps --crl

assert_file "$PKI_MAIN/intermediates/apps/crl/intermediate.crl" "Intermediate CRL for apps exists"

run_ok   "Generate CRLs for all intermediates" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --crl

for ca in apps users vpn infra; do
  assert_file "$PKI_MAIN/intermediates/$ca/crl/intermediate.crl" "CRL for $ca exists"
done

########################################
# 13. INTERMEDIATE: revocation & CA validity checks
########################################

run_ok   "Revoke intermediate 'users' at Root level" \
  "$EASYPKI" int --pki-dir "$PKI_MAIN" --revoke-intermediate users --reason keyCompromise

run_fail "Issue user cert under revoked intermediate 'users' should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --ca users --issue-user evil-after-revoke

run_ok   "cert --crl after intermediate 'users' revoked (should skip users)" \
  "$EASYPKI" cert --pki-dir "$PKI_MAIN" --crl

########################################
# 14. PKI_ALT: minimal usage (no intermediates)
########################################

run_fail "Issue user cert in PKI_ALT with non-existing CA should fail" \
  "$EASYPKI" cert --pki-dir "$PKI_ALT" --ca nonexistent --issue-user someone

run_ok   "root --info on PKI_ALT" \
  "$EASYPKI" root --pki-dir "$PKI_ALT" --info

########################################
# 15. PKI_BROKEN: manually break things and see failures
########################################

# Create root correctly, then break index.txt
run_ok   "Create Root in PKI_BROKEN" \
  "$EASYPKI" root --pki-dir "$PKI_BROKEN" --country FR --state X --locality Y --org Broken --root-cn "Broken Root"

rm -f "$PKI_BROKEN/root/index.txt"

run_fail "Try to create intermediate with missing Root DB index.txt (PKI_BROKEN)" \
  "$EASYPKI" int --pki-dir "$PKI_BROKEN" -i apps

########################################
# SUMMARY
########################################

echo
echo "======================================="
echo "${T_BOLD}Test summary:${T_RESET}"
echo "  Passed: ${T_GREEN}$TESTS_OK${T_RESET}"
echo "  Total : ${T_CYAN}$TESTS_RUN${T_RESET}"
if [[ "$TESTS_OK" -eq "$TESTS_RUN" ]]; then
  echo "  RESULT: ${T_GREEN}${T_BOLD}ALL TESTS PASSED 🎉${T_RESET}"
else
  echo "  RESULT: ${T_RED}${T_BOLD}SOME TESTS FAILED ❌${T_RESET}"
fi
echo "Logs for last command are in:"
echo "  ${T_YELLOW}$BASE_DIR/log.out${T_RESET}"
echo "  ${T_YELLOW}$BASE_DIR/log.err${T_RESET}"
echo "Workspace kept at: ${T_BOLD}$BASE_DIR${T_RESET}"
