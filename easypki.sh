#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

# === LOGGING FUNCTIONS (shared) ===
log(){ printf '[*] %s\n' "$*"; }
ok(){  printf '[✔] %s\n' "$*"; }
err(){ printf '[x] %s\n' "$*" >&2; }

# === GLOBAL ERROR HANDLING ===
trap 'st=$?; err "Failed at line $LINENO: $BASH_COMMAND"; exit $st' ERR
set -o errtrace

# === COLOR HELP (shared) ===
_help_colors() {
  if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
    local n; n=$(tput colors 2>/dev/null || echo 0)
    if (( n >= 8 )); then
      BOLD="$(tput bold)"; RESET="$(tput sgr0)"
      CYAN="$(tput setaf 6)"; YELLOW="$(tput setaf 3)"; GREEN="$(tput setaf 2)"
      return
    fi
  fi
  BOLD=""; RESET=""; CYAN=""; YELLOW=""; GREEN=""
}

# === GENERIC HELPERS (shared) ===
is_uint(){ [[ "${1:-}" =~ ^[0-9]+$ ]]; }
trim(){ local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
_sn(){
  openssl x509 -in "$1" -noout -serial \
    | cut -d= -f2 \
    | tr '[:lower:]' '[:upper:]' \
    | sed 's/^0\+//'
}

# === MAIN HELP ===
main_help(){
  _help_colors
  cat <<EOF
${BOLD}easypki.sh${RESET} — homelab PKI helper (Root, Intermediates, End-entity certs)

${CYAN}SUBCOMMANDS${RESET}

  ${GREEN}./easypki.sh root${RESET} [options...]
      Create / inspect the Root CA

  ${GREEN}./easypki.sh int${RESET} [options...]
      Create / inspect / revoke Intermediate CAs

  ${GREEN}./easypki.sh cert${RESET} [options...]
      Manage issued certificates: issue / revoke / list / info / CRL

For detailed help of each subcommand:
  ${GREEN}./easypki.sh root --help${RESET}
  ${GREEN}./easypki.sh int --help${RESET}
  ${GREEN}./easypki.sh cert --help${RESET}
EOF
}

########################################
#   SUBCOMMAND: ROOT
########################################

root_help(){
  _help_colors
  cat <<EOF
${BOLD}./easypki.sh root${RESET} — create or inspect the Root CA

${CYAN}USAGE${RESET}
  ${GREEN}./easypki.sh root${RESET} [--pki-dir DIR] [DN options] [VALIDITY options]
      Create the Root CA if missing (idempotent).
  ${GREEN}./easypki.sh root${RESET} [--pki-dir DIR] --info
      Show detailed recap of the existing Root CA, and status of all Intermediates.
  ${GREEN}./easypki.sh root${RESET} [--pki-dir DIR] --renew-crl
      Renew the Root CRL.

${CYAN}DN OPTIONS${RESET} (generic defaults)
  ${BOLD}--country${RESET} C           e.g. FR
  ${BOLD}--state${RESET} "ST"          e.g. "Ile-de-France"
  ${BOLD}--locality${RESET} "L"        e.g. "Paris"
  ${BOLD}--org${RESET} "O"             e.g. "Homelab"
  ${BOLD}--root-cn${RESET} "CN"        e.g. "Homelab Root CA"

${CYAN}VALIDITY & CRL${RESET}
  ${BOLD}--root-days${RESET} N          default: ${YELLOW}7300${RESET}
  ${BOLD}--crl-days-root${RESET} N      default: ${YELLOW}7300${RESET}
  ${BOLD}--serial-start${RESET} N       default: ${YELLOW}1000${RESET}

${CYAN}FILES / LAYOUT${RESET}
  <pki-dir>/root/
    certs/ca.cert.pem
    private/ca.key.pem         # AES-256, passphrase prompted
    crl/root.crl
    openssl.cnf
  (default ${BOLD}--pki-dir${RESET}: ${YELLOW}./pki${RESET})
EOF
}

root_main(){
  # Defaults
  PKI_DIR="./pki"
  SHOW_INFO=0
  RENEW_CRL=0
  OUTPUT_JSON=0
  DN_COUNTRY="XX"
  DN_STATE="State"
  DN_LOCALITY="City"
  DN_ORG="Organization"
  ROOT_CN="Root CA"
  ROOT_DAYS=7300
  CRL_DAYS_ROOT=7300
  SERIAL_START=1000

  # Args
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) root_help; exit 0 ;;
      --pki-dir) PKI_DIR="$2"; shift 2 ;;
      --info) SHOW_INFO=1; shift ;;
      --renew-crl) RENEW_CRL=1; shift ;;
      --json) OUTPUT_JSON=1; shift ;;
      --country) DN_COUNTRY="$2"; shift 2 ;;
      --state) DN_STATE="$2"; shift 2 ;;
      --locality) DN_LOCALITY="$2"; shift 2 ;;
      --org) DN_ORG="$2"; shift 2 ;;
      --root-cn) ROOT_CN="$2"; shift 2 ;;
      --root-days) ROOT_DAYS="$2"; shift 2 ;;
      --crl-days-root) CRL_DAYS_ROOT="$2"; shift 2 ;;
      --serial-start) SERIAL_START="$2"; shift 2 ;;
      --) shift; break ;;
      -*) err "Unknown option $1"; root_help; exit 1 ;;
      *)  err "Unexpected arg $1"; root_help; exit 1 ;;
    esac
  done

  # Validations
  for v in "$ROOT_DAYS" "$CRL_DAYS_ROOT" "$SERIAL_START"; do
    is_uint "$v" || { err "Invalid number: $v"; exit 1; }
  done

  [[ -n "$DN_COUNTRY" && -n "$DN_STATE" && -n "$DN_ORG" ]] || { err "Empty DN field (C/ST/O)"; exit 1; }
  [[ -n "$DN_LOCALITY" ]] || { err "Empty DN field (L)"; exit 1; }

  (( CRL_DAYS_ROOT <= ROOT_DAYS )) || { err "--crl-days-root must be <= --root-days"; exit 1; }

  command -v openssl >/dev/null 2>&1 || { err "openssl not found"; exit 1; }

  # Paths
  mkdir -p "$PKI_DIR"
  [[ -w "$PKI_DIR" ]] || { err "Not writable: $PKI_DIR"; exit 1; }
  PKI_DIR="$(cd "$PKI_DIR" && pwd)"
  ROOT="$PKI_DIR/root"
  CONF="$ROOT/openssl.cnf"
  CRT="$ROOT/certs/ca.cert.pem"
  CRL="$ROOT/crl/root.crl"
  DB="$ROOT/index.txt"

  _db(){ awk -F'\t' -v s="$1" 'toupper($4)==s{print;exit}' "$DB" 2>/dev/null || true; }
  _na(){ openssl x509 -in "$1" -noout -enddate | cut -d= -f2; }

  # Info mode
  if (( SHOW_INFO )); then
    if [[ -f "$CRT" ]]; then
      echo "Subject     : $(openssl x509 -in "$CRT" -noout -subject | sed 's/^subject= //')"
      echo "Issuer      : $(openssl  x509 -in "$CRT" -noout -issuer  | sed 's/^issuer= //')"
      echo "Validity    : $(openssl x509 -in "$CRT" -noout -startdate | sed 's/^notBefore=//') → $(openssl x509 -in "$CRT" -noout -enddate | sed 's/^notAfter=//')"
      echo "Serial      : $(openssl  x509 -in "$CRT" -noout -serial | sed 's/^serial=//')"
      echo "Fingerprint : $(openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=//')"
      kb="$(openssl x509 -in "$CRT" -noout -text | sed -n 's/.*Public-Key: (\([0-9]\+\) bit).*/\1/p' | head -n1)"
      [[ -n "$kb" ]] && echo "Key Bits    : $kb"
    else
      echo "(missing: $CRT)"
    fi
    if [[ -f "$CRL" ]]; then
      echo "CRL         : $CRL"
      echo "CRL Issuer  : $(openssl crl -in "$CRL" -noout -issuer | sed 's/^issuer=//')"
      echo "CRL Update  : last=$(openssl crl -in "$CRL" -noout -lastupdate | sed 's/^lastUpdate=//')  next=$(openssl crl -in "$CRL" -noout -nextupdate | sed 's/^nextUpdate=//')"
    else
      echo "(CRL missing: $CRL)"
    fi
    if [[ -f "$DB" ]]; then
      v=$(grep -cE '^V' "$DB" || true); r=$(grep -cE '^R' "$DB" || true); e=$(grep -cE '^E' "$DB" || true); t=$(wc -l < "$DB" || true)
      echo "DB entries  : total=$t  valid=$v  revoked=$r  expired=$e"
    fi

    INT_BASE="$PKI_DIR/intermediates"
    if [[ -d "$INT_BASE" ]]; then
      echo; echo "Intermediates (issued by Root):"; shopt -s nullglob
      for d in "$INT_BASE"/*; do
        [[ -d "$d" ]] || continue
        name="${d##*/}"; ic="$d/certs/intermediate.cert.pem"
        [[ -f "$ic" ]] || { printf '  - %-18s : (missing certificate)\n' "$name"; continue; }

        norm="$(_sn "$ic")"
        row="$(_db "$norm")"
        if [[ -n "$row" ]]; then
          IFS=$'\t' read -r code exp rev _ <<<"$row"
          case "$code" in
            V) status="Valid";   extra=" (notAfter: $(_na "$ic"))" ;;
            R) status="Revoked"; rdate="${rev%%,*}"; rreason="${rev#*,}"; [[ "$rreason" == "$rev" ]] && rreason="unspecified"
               extra=" (revoked: $rdate, reason: $rreason)" ;;
            E) status="Expired"; extra=" (expired: $exp)" ;;
            *) status="unknown"; extra="" ;;
          esac
        else
          status="unknown"; extra=""
        fi
        printf '%-11s : %s%s\n' "$name" "$status" "$extra"
      done
    fi
    exit 0
  fi

  # Renew CRL
  if (( RENEW_CRL )); then
    if [[ -f "$CONF" && -f "$CRT" && -f "$ROOT/private/ca.key.pem" && -f "$DB" ]]; then
      log "Renew Root CRL..."
      ( cd "$ROOT" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/root.crl" )
      chmod 644 "$CRL"
      ok "CRL renewed"
      exit 0
    else
      err "Root not initialized"; exit 1
    fi
  fi

  if [[ -f "$CRT" ]]; then ok "Root exists, nothing to do."; exit 0; fi

  # Root CA creation
  log "Prepare directories..."
  mkdir -p "$ROOT"/{certs,crl,newcerts,private}
  chmod 700 "$ROOT" "$ROOT/private"
  chmod 755 "$ROOT"/{certs,crl,newcerts}
  : > "$DB"
  [[ -f "$ROOT/index.txt.attr" ]] || echo "unique_subject = no" > "$ROOT/index.txt.attr"
  echo "$SERIAL_START" > "$ROOT/serial"
  echo "$SERIAL_START" > "$ROOT/crlnumber"

  log "Write openssl.cnf..."
  cat > "$CONF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/root.crl
crl_extensions    = crl_ext
default_crl_days  = ${CRL_DAYS_ROOT}
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${ROOT_DAYS}
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
default_md          = sha256
prompt              = no
distinguished_name  = req_dn
x509_extensions     = v3_ca

[ req_dn ]
C  = ${DN_COUNTRY}
ST = ${DN_STATE}
L  = ${DN_LOCALITY}
O  = ${DN_ORG}
CN = ${ROOT_CN}

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, keyCertSign, cRLSign

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
EOF
  chmod 644 "$CONF"

  if [[ "${EASYPKI_INSECURE_NO_PASSPHRASE:-0}" == "1" ]]; then
    log "Generate UNENCRYPTED private key (INSECURE / TEST MODE)..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$ROOT/private/ca.key.pem"
  else
    log "Generate encrypted private key..."
    openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -out "$ROOT/private/ca.key.pem"
  fi
  chmod 600 "$ROOT/private/ca.key.pem"

  log "Self-sign Root certificate..."
  openssl req -config "$CONF" -key "$ROOT/private/ca.key.pem" -new -x509 -days "$ROOT_DAYS" -sha256 -extensions v3_ca -out "$CRT"
  chmod 644 "$CRT"

  log "Generate Root CRL..."
  ( cd "$ROOT" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/root.crl" )
  chmod 644 "$CRL"

  ok "Root ready"
  if (( OUTPUT_JSON )); then
    printf '{ "cert":"%s","key":"%s","crl":"%s" }\n' "$CRT" "$ROOT/private/ca.key.pem" "$CRL"
  else
    echo "cert: $CRT"
    echo "key : $ROOT/private/ca.key.pem"
    echo "crl : $CRL"
  fi
}

########################################
#   SUBCOMMAND: INT
########################################

int_help(){
  _help_colors
  cat <<EOF
${BOLD}./easypki.sh int${RESET} — create or inspect Intermediate CAs

${CYAN}USAGE${RESET}
  ${GREEN}./easypki.sh int${RESET} [--pki-dir DIR] -i NAME [-i NAME2 ...] [DN options] [VALIDITY options]
      Create one or more Intermediate CAs (idempotent).
  ${GREEN}./easypki.sh int${RESET} [--pki-dir DIR] --info
      Show detailed recap for all existing Intermediates.
  ${GREEN}./easypki.sh int${RESET} [--pki-dir DIR] --revoke-intermediate NAME [--reason REASON]
      Revoke an Intermediate CA (revoked by the Root CA) and update the Root CRL.

${CYAN}DN OPTIONS${RESET} (generic defaults)
  ${BOLD}--country${RESET} C             e.g. FR
  ${BOLD}--state${RESET} "ST"            e.g. "Ile-de-France"
  ${BOLD}--locality${RESET} "L"          e.g. "Paris"
  ${BOLD}--org${RESET} "O"               e.g. "Homelab"
  ${BOLD}--int-cn-prefix${RESET} "PREF"  e.g. "Homelab Intermediate CA - "

${CYAN}VALIDITY & CRL${RESET}
  ${BOLD}--int-days${RESET} N            default: ${YELLOW}3650${RESET}
  ${BOLD}--crl-days-int${RESET} N        default: ${YELLOW}3650${RESET}
  ${BOLD}--serial-start${RESET} N        default: ${YELLOW}1000${RESET}

${CYAN}FILES / LAYOUT${RESET}
  <pki-dir>/intermediates/<NAME>/
    certs/intermediate.cert.pem
    private/intermediate.key.pem
    csr/intermediate.csr.pem
    crl/intermediate.crl
    index.txt / serial / crlnumber / openssl.cnf
  <pki-dir>/chain/<NAME>.chain.pem
  (default ${BOLD}--pki-dir${RESET}: ${YELLOW}./pki${RESET})
EOF
}

int_main(){
  PKI_DIR="./pki"
  SHOW_INFO=0
  INTERM=()
  DN_COUNTRY="XX"
  DN_STATE="State"
  DN_LOCALITY="City"
  DN_ORG="Organization"
  INT_CN_PREFIX="Intermediate CA - "
  INT_DAYS=3650
  CRL_DAYS_INT=3650
  SERIAL_START=1000
  REVOKE_INT=""
  REVOKE_REASON="unspecified"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) int_help; exit 0 ;;
      --pki-dir) PKI_DIR="$2"; shift 2 ;;
      --info) SHOW_INFO=1; shift ;;
      -i|--intermediate) INTERM+=("$2"); shift 2 ;;
      --country) DN_COUNTRY="$2"; shift 2 ;;
      --state) DN_STATE="$2"; shift 2 ;;
      --locality) DN_LOCALITY="$2"; shift 2 ;;
      --org) DN_ORG="$2"; shift 2 ;;
      --int-cn-prefix) INT_CN_PREFIX="$2"; shift 2 ;;
      --int-days) INT_DAYS="$2"; shift 2 ;;
      --crl-days-int) CRL_DAYS_INT="$2"; shift 2 ;;
      --serial-start) SERIAL_START="$2"; shift 2 ;;
      --revoke-intermediate) REVOKE_INT="$2"; shift 2 ;;
      --reason) REVOKE_REASON="$2"; shift 2 ;;
      --) shift; break ;;
      -*) err "Unknown option $1"; int_help; exit 1 ;;
      *)  err "Unexpected arg $1"; int_help; exit 1 ;;
    esac
  done

  for v in "$INT_DAYS" "$CRL_DAYS_INT" "$SERIAL_START"; do
    is_uint "$v" || { err "Invalid number: $v"; exit 1; };
  done

  [[ -n "$(trim "$DN_COUNTRY")" && -n "$(trim "$DN_STATE")" && -n "$(trim "$DN_ORG")" ]] || { err "Empty DN field (C/ST/O)"; exit 1; }
  [[ -n "$DN_LOCALITY" ]] || { err "Empty DN field (L)"; exit 1; }

  (( CRL_DAYS_INT <= INT_DAYS )) || { err "--crl-days-int must be <= --int-days"; exit 1; }

  command -v openssl >/dev/null 2>&1 || { err "openssl not found"; exit 1; }
  [[ ${#INTERM[@]} -gt 0 || $SHOW_INFO -eq 1 || -n "$REVOKE_INT" ]] || { int_help; exit 1; }

  mkdir -p "$PKI_DIR"
  [[ -w "$PKI_DIR" ]] || { err "Not writable: $PKI_DIR"; exit 1; }
  PKI_DIR="$(cd "$PKI_DIR" && pwd)"
  ROOT="$PKI_DIR/root"
  ROOT_CNF="$ROOT/openssl.cnf"
  ROOT_CRT="$ROOT/certs/ca.cert.pem"
  INT_BASE="$PKI_DIR/intermediates"
  CHAIN_DIR="$PKI_DIR/chain"

  need_root(){
    [[ -f "$ROOT_CNF" && -f "$ROOT_CRT" && -f "$ROOT/private/ca.key.pem" && -f "$ROOT/index.txt" ]] \
      || { err "Root missing or incomplete in $ROOT (run 'easypki.sh root')"; exit 1; }
  }

  _root_db_row_by_cert(){
    local cert="$1" sn
    [[ -f "$ROOT/index.txt" ]] || { echo ""; return 0; }
    sn="$(_sn "$cert")"
    awk -F'\t' -v s="$sn" 'toupper($4)==s{print;exit}' "$ROOT/index.txt" 2>/dev/null || true
  }

  _print_root_status(){
    local cert="$1" row code exp rev
    row="$(_root_db_row_by_cert "$cert")"
    if [[ -z "$row" ]]; then
      echo "Status      : unknown in Root DB"
      return
    fi
    IFS=$'\t' read -r code exp rev _ _ <<<"$row"
    case "$code" in
      V)
        local na; na="$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')"
        echo "Status      : Valid (notAfter: $na)"
        ;;
      R)
        local rdate="${rev%%,*}"; local rreason="${rev#*,}"; [[ "$rreason" == "$rev" ]] && rreason="unspecified"
        echo "Status      : Revoked (revoked: $rdate, reason: $rreason)"
        ;;
      E)
        echo "Status      : Expired (expired: $exp)"
        ;;
      *)
        echo "Status      : unknown ($code)"
        ;;
    esac
  }

  if (( SHOW_INFO )); then
    if [[ -d "$INT_BASE" ]]; then
      shopt -s nullglob
      for d in "$INT_BASE"/*; do
        [[ -d "$d" ]] || continue
        name="$(basename -- "$d")"
        ic="$d/certs/intermediate.cert.pem"; icrl="$d/crl/intermediate.crl"; chain="$CHAIN_DIR/$name.chain.pem"
        echo "-- $name --"
        if [[ -f "$ic" ]]; then
          echo "Subject     : $(openssl x509 -in "$ic" -noout -subject | sed 's/^subject= //')"
          echo "Issuer      : $(openssl  x509 -in "$ic" -noout -issuer  | sed 's/^issuer= //')"
          echo "Validity    : $(openssl x509 -in "$ic" -noout -startdate | sed 's/^notBefore=//') → $(openssl x509 -in "$ic" -noout -enddate | sed 's/^notAfter=//')"
          echo "Serial      : $(openssl  x509 -in "$ic" -noout -serial | sed 's/^serial=//')"
          echo "Fingerprint : $(openssl x509 -in "$ic" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=//')"
          kb="$(openssl x509 -in "$ic" -noout -text | sed -n 's/.*Public-Key: (\([0-9]\+\) bit).*/\1/p' | head -n1)"
          [[ -n "$kb" ]] && echo "Key Bits    : $kb"
          _print_root_status "$ic"
        else
          echo "(missing: $ic)"
        fi
        if [[ -f "$icrl" ]]; then
          echo "CRL         : $icrl"
          echo "CRL Issuer  : $(openssl crl -in "$icrl" -noout -issuer | sed 's/^issuer=//')"
          echo "CRL Update  : last=$(openssl crl -in "$icrl" -noout -lastupdate | sed 's/^lastUpdate=//')  next=$(openssl crl -in "$icrl" -noout -nextupdate | sed 's/^nextUpdate=//')"
        else
          echo "(CRL missing: $icrl)"
        fi

        if [[ -f "$d/index.txt" ]]; then
          v=$(grep -cE '^V' "$d/index.txt" || true); r=$(grep -cE '^R' "$d/index.txt" || true); e=$(grep -cE '^E' "$d/index.txt" || true); t=$(wc -l < "$d/index.txt" || true)
          echo "DB entries  : total=$t  valid=$v  revoked=$r  expired=$e"
        fi
        if [[ -f "$chain" && -f "$ic" ]]; then
          openssl verify -CAfile "$chain" "$ic" >/dev/null 2>&1 && echo "Chain Verify: OK" || echo "Chain Verify: FAILED"
        fi
        echo
      done
    else
      echo "(none)"
    fi
    exit 0
  fi

  if [[ -n "$REVOKE_INT" ]]; then
    need_root
    [[ "$REVOKE_INT" =~ ^[A-Za-z0-9._-]+$ ]] || { err "Invalid intermediate name: $REVOKE_INT"; exit 1; }
    ICERT="$INT_BASE/$REVOKE_INT/certs/intermediate.cert.pem"
    [[ -f "$ICERT" ]] || { err "Intermediate cert not found: $ICERT"; exit 1; }
    log "Revoke intermediate '$REVOKE_INT' (reason: $REVOKE_REASON)..."
    ( cd "$ROOT" && openssl ca -batch -config "openssl.cnf" -revoke "$ICERT" -crl_reason "$REVOKE_REASON" )
    ( cd "$ROOT" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/root.crl" )
    chmod 644 "$ROOT/crl/root.crl"
    ok "Intermediate '$REVOKE_INT' revoked. Root CRL updated."
    exit 0
  fi

  need_root
  mkdir -p "$INT_BASE" "$CHAIN_DIR"

  for NAME in "${INTERM[@]}"; do
    [[ -n "$(trim "$NAME")" ]] || { err "Empty intermediate name"; exit 1; }
    [[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { err "Invalid intermediate name: $NAME"; exit 1; }
    INT_DIR="$INT_BASE/$NAME"; CNF="$INT_DIR/openssl.cnf"
    if [[ -f "$INT_DIR/certs/intermediate.cert.pem" ]]; then ok "Intermediate '$NAME' exists, skip."; continue; fi

    log "Create '$NAME'..."
    mkdir -p "$INT_DIR"/{certs,crl,csr,newcerts,private}
    chmod 700 "$INT_DIR/private"
    : > "$INT_DIR/index.txt"
    echo "unique_subject = no" > "$INT_DIR/index.txt.attr"
    echo "$SERIAL_START" > "$INT_DIR/serial"
    echo "$SERIAL_START" > "$INT_DIR/crlnumber"

    log "Write openssl.cnf..."
    cat > "$CNF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
private_key       = \$dir/private/intermediate.key.pem
certificate       = \$dir/certs/intermediate.cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/intermediate.crl
crl_extensions    = crl_ext
default_crl_days  = ${CRL_DAYS_INT}
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${INT_DAYS}
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
default_md          = sha256
prompt              = no
distinguished_name  = req_dn
string_mask         = utf8only
x509_extensions     = v3_intermediate_ca

[ req_dn ]
C  = ${DN_COUNTRY}
ST = ${DN_STATE}
L  = ${DN_LOCALITY}
O  = ${DN_ORG}
CN = ${INT_CN_PREFIX}${NAME}

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign

[ usr_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth

[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF
    chmod 644 "$CNF"

    log "Key (RSA 4096, unencrypted)..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$INT_DIR/private/intermediate.key.pem"
    chmod 600 "$INT_DIR/private/intermediate.key.pem"

    log "CSR..."
    openssl req -config "$CNF" -new -sha256 -key "$INT_DIR/private/intermediate.key.pem" -out "$INT_DIR/csr/intermediate.csr.pem"

    CSR_ABS="$INT_DIR/csr/intermediate.csr.pem"
    CRT_ABS="$INT_DIR/certs/intermediate.cert.pem"

    log "Sign with Root..."
    ( cd "$ROOT" && openssl ca -batch -config "openssl.cnf" -extensions v3_intermediate_ca -days "$INT_DAYS" -notext -md sha256 -in "$CSR_ABS" -out "$CRT_ABS" )
    chmod 644 "$CRT_ABS"

    log "Chain..."
    cat "$CRT_ABS" "$ROOT_CRT" > "$CHAIN_DIR/${NAME}.chain.pem"
    chmod 644 "$CHAIN_DIR/${NAME}.chain.pem"

    log "CRL..."
    ( cd "$INT_DIR" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/intermediate.crl" )
    chmod 644 "$INT_DIR/crl/intermediate.crl"

    ok "Intermediate '$NAME' ready."
  done

  ok "Done."
}

########################################
#   SUBCOMMAND: CERT
########################################

cert_help(){
  _help_colors
  cat <<EOF
${BOLD}./easypki.sh cert${RESET} — issue / revoke / list / info for end-entity certs

${CYAN}USAGE${RESET}
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --ca CA --issue-user NAME  [--days N] [--replace]
      Issue a user/client certificate (profile: clientAuth).
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --ca CA --issue-server FQDN [--days N] [--san VAL]... [--replace]
      Issue a server certificate (profile: serverAuth; SANs via --san).
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --ca CA --revoke NAME
      Revoke an end-entity certificate and update the CA CRL.
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --ca CA --crl
      Regenerate the CRL for a specific Intermediate CA.
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --crl
      Regenerate the CRL for all Intermediates.
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --list
      List DB entries for all Intermediates (or a specific one with --ca).
  ${GREEN}./easypki.sh cert${RESET} [--pki-dir DIR] --ca CA --info NAME
      Show detailed info for a specific issued certificate.
EOF
}

cert_main(){
  PKI_DIR="./pki"
  CA=""
  ACT=""
  NAME=""
  DAYS=1825
  KEY_BITS=2048
  SANS=()
  REPLACE=0

  need_val(){ [[ $# -ge 2 && -n "${2:-}" ]] || { err "Missing value for $1"; exit 1; }; }

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) cert_help; exit 0 ;;
      --pki-dir) need_val "$1" "$2"; PKI_DIR="$2"; shift 2 ;;
      --ca)      need_val "$1" "$2"; CA="$2"; shift 2 ;;
      --days)    need_val "$1" "$2"; DAYS="$2"; shift 2 ;;
      --san)     need_val "$1" "$2"; SANS+=("$2"); shift 2 ;;
      --replace) REPLACE=1; shift ;;
      --issue-user)   need_val "$1" "$2"; ACT="ISSUE_USER"; NAME="$2"; shift 2 ;;
      --issue-server) need_val "$1" "$2"; ACT="ISSUE_SERVER"; NAME="$2"; shift 2 ;;
      --revoke)       need_val "$1" "$2"; ACT="REVOKE";      NAME="$2"; shift 2 ;;
      --list)         ACT="LIST"; shift ;;
      --info)         need_val "$1" "$2"; ACT="INFO"; NAME="$2"; shift 2 ;;
      --crl)          ACT="CRL"; shift ;;
      --) shift; break ;;
      -*) err "Unknown option $1"; cert_help; exit 1 ;;
      *)  err "Unexpected arg $1"; cert_help; exit 1 ;;
    esac
  done

  sanitize_name(){ [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || { err "Invalid NAME '$1'"; exit 1; }; }

  command -v openssl >/dev/null 2>&1 || { err "openssl not found"; exit 1; }
  is_uint "$DAYS" || { err "--days must be an integer"; exit 1; }
  [[ -n "${ACT:-}" ]] || { cert_help; exit 1; }
  [[ -n "${NAME:-}" ]] && sanitize_name "$NAME"

  mkdir -p "$PKI_DIR"
  [[ -w "$PKI_DIR" ]] || { err "Not writable: $PKI_DIR"; exit 1; }
  PKI_DIR="$(cd "$PKI_DIR" && pwd)"
  ROOT="$PKI_DIR/root"

  int_dir(){ echo "$PKI_DIR/intermediates/$1"; }
  int_conf(){ echo "$(int_dir "$1")/openssl.cnf"; }
  int_db(){ echo "$(int_dir "$1")/index.txt"; }
  int_crl(){ echo "$(int_dir "$1")/crl/intermediate.crl"; }
  chain(){ echo "$PKI_DIR/chain/$1.chain.pem"; }
  issued(){
    local ca="$1"
    local n="${2:?missing NAME for issued()}"
    echo "$(int_dir "$ca")/issued/$n"
  }
  need_root(){
    [[ -f "$ROOT/openssl.cnf" && -f "$ROOT/certs/ca.cert.pem" && -f "$ROOT/index.txt" ]] \
      || { err "Root missing or incomplete in $ROOT (run 'easypki.sh root')"; exit 1; }
  }
  need_ca(){
    local c="$1"
    [[ -n $c ]] || { err "--ca required"; exit 1; }
    [[ -f "$(int_conf "$c")" && -f "$(int_dir "$c")/private/intermediate.key.pem" && -f "$(int_db "$c")" ]] \
      || { err "CA '$c' missing or incomplete (run 'easypki.sh int')"; exit 1; }
  }
  need_name(){ [[ -n "$NAME" ]] || { err "NAME required"; exit 1; }; }

  normalize_sans(){
    local raw=("${SANS[@]}") out=() item parts part
    declare -A seen=()
    for item in "${raw[@]}"; do
      IFS=',' read -r -a parts <<< "$item"
      for part in "${parts[@]}"; do
        part="${part#"${part%%[![:space:]]*}"}"; part="${part%"${part##*[![:space:]]}"}"
        [[ -z $part ]] && continue
        [[ "$part" == DNS:* || "$part" == IP:* ]] || part="DNS:$part"
        [[ -z "${seen[$part]:-}" ]] && { out+=("$part"); seen[$part]=1; }
      done
    done
    SANS=("${out[@]}")
  }

  write_san_ext(){
    local ca="$1" n="$2" d ext
    d="$(issued "$ca" "$n")"; ext="$d/$n.san.cnf"; normalize_sans; : > "$ext"
    [[ ${#SANS[@]} -eq 0 ]] && { echo "$ext"; return; }
    local i=1
    cat > "$ext" <<EOF
[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt

[ alt ]
EOF
    for e in "${SANS[@]}"; do
      case "$e" in
        DNS:*) echo "DNS.$i = ${e#DNS:}" >> "$ext" ;;
        IP:*)  echo "IP.$i  = ${e#IP:}"  >> "$ext" ;;
      esac
      i=$((i+1))
    done
    echo "$ext"
  }

  _db_row(){ awk -F'\t' -v s="$1" 'toupper($4)==s{print;exit}' "$(int_db "$2")" 2>/dev/null || true; }

  revoke_cert_file_if_valid(){
    local ca="$1" c="$2"
    [[ -f "$c" ]] || return 0
    local ser row code
    ser="$(_sn "$c")"
    row="$(_db_row "$ser" "$ca")"
    [[ -n "$row" ]] || return 0
    code="${row%%[[:space:]]*}"
    if [[ "$code" == "V" ]]; then
      log "Revoke existing certificate (serial $ser)..."
      ( cd "$(int_dir "$ca")" && openssl ca -batch -config "openssl.cnf" -revoke "$c" )
      log "CRL..."
      ( cd "$(int_dir "$ca")" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/intermediate.crl" )
      chmod 644 "$(int_crl "$ca")"
    fi
  }

  rotate_old_issue_dir(){
    local ca="$1" n="$2" d newd ts
    d="$(issued "$ca" "$n")"
    [[ -d "$d" ]] || return 0
    ts="$(date -u +%Y%m%d%H%M%S)"
    newd="${d}.revoked-${ts}"
    log "Rotate issued dir → ${newd}"
    mv "$d" "$newd"
  }

  root_db_row_by_cert(){
    local cert="$1" sn
    [[ -f "$ROOT/index.txt" ]] || { err "Root DB missing: $ROOT/index.txt"; exit 1; }
    sn="$(_sn "$cert")"
    awk -F'\t' -v s="$sn" 'toupper($4)==s{print;exit}' "$ROOT/index.txt" 2>/dev/null || true
  }

  ca_valid_in_root_quiet(){
    local ca="$1" cert row code
    cert="$(int_dir "$ca")/certs/intermediate.cert.pem"
    [[ -f "$cert" ]] || return 1
    row="$(root_db_row_by_cert "$cert")"
    [[ -n "$row" ]] || return 1
    code="${row%%$'\t'*}"
    [[ "$code" == "V" ]]
  }

  assert_ca_valid_in_root(){
    local ca="$1" cert row code revinfo
    cert="$(int_dir "$ca")/certs/intermediate.cert.pem"
    [[ -f "$cert" ]] || { err "Intermediate cert missing for '$ca'"; exit 1; }
    row="$(root_db_row_by_cert "$cert")"
    [[ -n "$row" ]] || { err "Intermediate '$ca' not found in Root DB; refusing operation."; exit 1; }
    code="${row%%$'\t'*}"
    case "$code" in
      V) return 0 ;;
      R)
        revinfo="$(printf '%s' "$row" | awk -F'\t' '{print $3}')"
        err "Intermediate '$ca' is REVOKED by Root ($revinfo). Refusing operation."
        exit 1
        ;;
      E)
        err "Intermediate '$ca' is EXPIRED in Root DB. Refusing operation."
        exit 1
        ;;
      *)
        err "Intermediate '$ca' status unknown in Root DB. Refusing operation."
        exit 1
        ;;
    esac
  }

  issue(){
    local ca="$1" n="$2" profile="$3"
    need_root; need_ca "$ca"; assert_ca_valid_in_root "$ca"; need_name
    local d; d="$(issued "$ca" "$n")"; mkdir -p "$d"; chmod 700 "$d"
    local key="$d/$n.key.pem" csr="$d/$n.csr.pem" crt="$d/$n.cert.pem" fch="$d/$n.fullchain.pem" chn; chn="$(chain "$ca")"

    if [[ -f "$crt" ]]; then
      if (( REPLACE )); then
        revoke_cert_file_if_valid "$ca" "$crt"
        rotate_old_issue_dir "$ca" "$n"
        mkdir -p "$d"; chmod 700 "$d"
      else
        err "Cert exists: $crt"
        exit 1
      fi
    fi

    log "Key ($KEY_BITS bits RSA)..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$KEY_BITS" -out "$key"
    chmod 600 "$key"
    log "CSR (CN=$n)..."
    openssl req -new -sha256 -key "$key" -out "$csr" -subj "/CN=$n"

    local ext=()
    if [[ "$profile" == "server_cert" ]]; then
      local extfile; extfile="$(write_san_ext "$ca" "$n")"
      [[ -s "$extfile" ]] && ext=( -extfile "$extfile" )
    fi

    log "Sign ($profile, $DAYS days)..."
    ( cd "$(int_dir "$ca")" && openssl ca -batch -config "openssl.cnf" \
        -extensions "$profile" "${ext[@]}" -days "$DAYS" -notext -md sha256 \
        -in "$csr" -out "$crt" )
    chmod 644 "$crt"

    [[ -f "$chn" ]] && { cat "$crt" "$chn" > "$fch"; chmod 644 "$fch"; }

    ok "Issued"
    echo "Key       : $key"
    echo "CSR       : $csr"
    echo "Cert      : $crt"
    [[ -f "$fch" ]] && echo "Fullchain : $fch"
  }

  revoke(){
    local ca="$1" n="$2"; need_ca "$ca"; assert_ca_valid_in_root "$ca"; need_name
    local c
    c="$(issued "$ca" "$n")/$n.cert.pem"
    [[ -f $c ]] || c="$(int_dir "$ca")/certs/$n.cert.pem"
    [[ -f $c ]] || { err "Cert not found: $n"; exit 1; }

    log "Revoke..."
    ( cd "$(int_dir "$ca")" && openssl ca -batch -config "openssl.cnf" -revoke "$c" )

    log "CRL..."
    ( cd "$(int_dir "$ca")" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/intermediate.crl" )
    chmod 644 "$(int_crl "$ca")"
    ok "Revoked + CRL updated"
  }

  list_one(){
    local ca="$1"; need_ca "$ca"
    local db; db="$(int_db "$ca")"
    [[ -f $db ]] || { echo "[$ca] empty"; return; }
    echo "[$ca] $(wc -l < "$db") entries"
    awk -F'\t' '{
      dn = $NF
      cn = dn
          sub(/.*CN[ =]/, "", cn)
      sub(/[,/].*$/, "", cn)
      printf("  %-1s | %s | %s | %s\n", $1, $2, $3, cn)
    }' "$db"
  }

  list_all(){
    if [[ -n "$CA" ]]; then
      list_one "$CA"
    else
      local base="$PKI_DIR/intermediates"; [[ -d $base ]] || { echo "(no CA)"; return; }
      shopt -s nullglob
      for d in "$base"/*; do
        [[ -d "$d" ]] || continue
        list_one "$(basename "$d")"
      done
    fi
  }

  info(){
    local ca="$1" n="$2"; need_ca "$ca"; need_name
    local c
    c="$(issued "$ca" "$n")/$n.cert.pem"
    [[ -f $c ]] || c="$(int_dir "$ca")/certs/$n.cert.pem"
    [[ -f $c ]] || { err "Certificate for '$n' under CA '$ca' not found."; exit 1; }

    openssl x509 -in "$c" -noout -subject -issuer -startdate -enddate -serial -fingerprint -sha256

    local ser row code exp rev rdate rreason
    ser="$(_sn "$c")"
    row="$(_db_row "$ser" "$ca")"
    if [[ -n "$row" ]]; then
      IFS=$'\t' read -r code exp rev _rest <<<"$row"
      case "$code" in
        V)
          echo "Status: VALID"
          ;;
        R)
          rdate="${rev%%,*}"
          rreason="${rev#*,}"
          [[ "$rreason" == "$rev" ]] && rreason="unspecified"
          echo "Status: REVOKED (revoked: ${rdate:-unknown}; reason: ${rreason})"
          ;;
        E)
          echo "Status: EXPIRED (expired: ${exp})"
          ;;
        *)
          echo "Status: unknown in CA DB"
          ;;
      esac
    else
      echo "Status: not found in CA DB"
    fi

    local sans
    sans="$(openssl x509 -in "$c" -noout -ext subjectAltName 2>/dev/null | sed -n '1!{s/^[[:space:]]*//;p}' | paste -sd ',' - || true)"
    [[ -n "$sans" ]] && echo "SANs: $sans"

    echo "-- Public key --"
    openssl x509 -in "$c" -noout -text | sed -n 's/ *Subject Public Key Algorithm: */Algorithm: /p; s/ *Public-Key: (\([0-9]\+\) bit).*/Key bits: \1/p' | head -n 2

    local chn; chn="$(chain "$ca")"
    if [[ -f $chn ]]; then
      openssl verify -CAfile "$chn" "$c" >/dev/null 2>&1 && echo "Chain: OK" || echo "Chain: FAIL"
    else
      echo "Chain: (no chain file)"
    fi
  }

  crl_cmd(){
    if [[ -n "$CA" ]]; then
      need_ca "$CA"; assert_ca_valid_in_root "$CA"
      ( cd "$(int_dir "$CA")" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/intermediate.crl" )
      chmod 644 "$(int_crl "$CA")"
      ok "CRL updated: $(int_crl "$CA")"
    else
      local base="$PKI_DIR/intermediates"; [[ -d $base ]] || { err "no intermediates"; exit 1; }
      shopt -s nullglob
      for d in "$base"/*; do
        [[ -d "$d" ]] || continue
        local name; name="$(basename "$d")"
        if ! ca_valid_in_root_quiet "$name"; then
          err "Skipping CRL for '$name' (intermediate not valid in Root DB)"
          continue
        fi
        ( cd "$d" && openssl ca -batch -config "openssl.cnf" -gencrl -out "crl/intermediate.crl" )
        chmod 644 "$d/crl/intermediate.crl"
        ok "CRL: $d/crl/intermediate.crl"
      done
    fi
  }

  case "${ACT:-}" in
    ISSUE_USER)   [[ -n "$CA" ]] || { err "--ca required"; exit 1; }; issue "$CA" "$NAME" "usr_cert" ;;
    ISSUE_SERVER) [[ -n "$CA" ]] || { err "--ca required"; exit 1; }; issue "$CA" "$NAME" "server_cert" ;;
    REVOKE)       [[ -n "$CA" ]] || { err "--ca required"; exit 1; }; revoke "$CA" "$NAME" ;;
    LIST)         list_all ;;
    INFO)         [[ -n "$CA" ]] || { err "--ca required"; exit 1; }; info "$CA" "$NAME" ;;
    CRL)          crl_cmd ;;
    *)            cert_help; exit 1 ;;
  esac
}

# === GLOBAL DISPATCH ===
if [[ $# -lt 1 ]]; then
  main_help
  exit 1
fi

subcmd="$1"; shift || true

case "$subcmd" in
  root) root_main "$@" ;;
  int)  int_main  "$@" ;;
  cert) cert_main "$@" ;;
  -h|--help) main_help ;;
  *) err "Unknown subcommand: $subcmd"; main_help; exit 1 ;;
esac
