```
 _____                ____  _  _____
| ____|__ _ ___ _   _|  _ \| |/ /_ _|
|  _| / _` / __| | | | |_) | ' / | |
| |__| (_| \__ \ |_| |  __/| . \ | |
|_____\__,_|___/\__, |_|   |_|\_\___|
                |___/
```

`easypki` is a small Bash-based PKI helper for homelab / lab / small setups.

It manages:

- A **Root CA** (offline, long-lived)
- One or more **Intermediate CAs** (apps, users, vpn, etc.)
- **End-entity certificates** (users/clients and servers)
- **CRLs** (for Root and Intermediates)
- Simple **status / info** commands

All of this is done using `openssl` and a simple directory layout under a chosen `--pki-dir` (default: `./pki`).

There is also a test suite: `test_easypki.sh`, which creates several PKIs, runs many success / failure scenarios, and checks for edge cases.

---

## Features

- Fully self-contained: just `bash` + `openssl`.
- Clear separation between **Root**, **Intermediates**, and **end-entity** certs.
- Idempotent where it makes sense (re-running Root / Intermediates won’t destroy anything).
- Support for:
  - Client certificates (`clientAuth`)
  - Server certificates (`serverAuth`) with SANs (DNS & IP)
  - CRL generation and updates
  - Revocation of end-entity certs and Intermediate CAs
  - Simple status / info commands
- Simple, colored CLI output (where the terminal supports it).
- Optional **test-mode**: generate an unencrypted Root key via `EASYPKI_INSECURE_NO_PASSPHRASE=1` (for automated tests only).

---

## Requirements

- `bash` (script is written for Bash)
- `openssl`
- A POSIX-like environment (Linux, BSD, macOS, WSL, etc.)

Recommended: run the Root CA part on a **machine not exposed to the Internet** (or at least somewhere “offline” / safe).

---

## Files in this repository

- `easypki.sh`  
  Main PKI helper script.

- `test_easypki.sh`  
  Test suite that exercises many scenarios (happy paths, errors, edge cases).

---

## Installation

Clone or copy the files wherever you want, then:

```bash
chmod +x easypki.sh
chmod +x test_easypki.sh
```

You can either run `./easypki.sh` directly from the repo, or place it somewhere in your `$PATH`, for example:

```bash
cp easypki.sh /usr/local/bin/easypki
chmod +x /usr/local/bin/easypki
```

> In that case, just replace `./easypki.sh` in examples with `easypki`.

---

## Basic concepts & directory layout

By default, everything lives under `./pki` (you can override this with `--pki-dir`).

### Root CA

`<pki-dir>/root/`:

- `certs/ca.cert.pem` – Root CA certificate  
- `private/ca.key.pem` – Root CA private key (encrypted by default)  
- `crl/root.crl` – Root CRL  
- `openssl.cnf` – OpenSSL config for this CA  
- `index.txt`, `serial`, `crlnumber`, `index.txt.attr` – OpenSSL CA database files

### Intermediate CAs

`<pki-dir>/intermediates/<NAME>/`:

- `certs/intermediate.cert.pem`
- `private/intermediate.key.pem`
- `csr/intermediate.csr.pem`
- `crl/intermediate.crl`
- `index.txt`, `serial`, `crlnumber`, `index.txt.attr`
- `openssl.cnf`

### Chains

`<pki-dir>/chain/<CA_NAME>.chain.pem`  
Chain file: `<Intermediate cert> + <Root cert>`

### Issued certificates

`<pki-dir>/intermediates/<CA_NAME>/issued/<NAME>/`:

- `<NAME>.key.pem` – private key (unencrypted)
- `<NAME>.csr.pem` – CSR
- `<NAME>.cert.pem` – leaf certificate
- `<NAME>.fullchain.pem` – leaf + chain (if chain exists)

---

## Global usage

```bash
./easypki.sh <subcommand> [options...]
```

Subcommands:

- `root` – manage the Root CA
- `int`  – manage Intermediate CAs
- `cert` – manage end-entity certificates

Help:

```bash
./easypki.sh --help
./easypki.sh root --help
./easypki.sh int  --help
./easypki.sh cert --help
```

---

## Root CA

### Create Root CA

Example:

```bash
./easypki.sh root   --pki-dir ./pki   --country FR   --state "Ile-de-France"   --locality "Paris"   --org "Homelab"   --root-cn "Homelab Root CA"
```

This will:

- Create `./pki/root/`
- Generate a **4096-bit RSA private key** (encrypted by default)
- Self-sign a Root certificate
- Initialize the Root CA database
- Generate a Root CRL

You will be prompted for a passphrase for the Root key (good for security).

> Re-running the same command is **idempotent**: if the Root already exists, it will not be recreated.

### Info about Root

```bash
./easypki.sh root --pki-dir ./pki --info
```

Shows:

- Subject / Issuer
- Validity period
- Serial, fingerprint, key size
- CRL status (if present)
- Root DB stats (valid, revoked, expired)
- Status of Intermediates issued by this Root (valid/expired/revoked)

### Renew Root CRL

```bash
./easypki.sh root --pki-dir ./pki --renew-crl
```

Regenerates the Root CRL from the Root CA database.

### JSON output (paths)

```bash
./easypki.sh root --pki-dir ./pki --json
```

Prints something like:

```json
{ "cert":"/absolute/path/to/ca.cert.pem","key":"/absolute/path/to/ca.key.pem","crl":"/absolute/path/to/root.crl" }
```

---

## Intermediate CAs

### Create intermediates

Example:

```bash
./easypki.sh int --pki-dir ./pki   -i apps   -i users   -i vpn   --country FR   --state "Ile-de-France"   --locality "Paris"   --org "Homelab"   --int-cn-prefix "Homelab Intermediate CA - "
```

This will:

- Create `<pki-dir>/intermediates/apps`, `users`, `vpn`
- Generate **4096-bit unencrypted RSA keys** for each Intermediate
- Create CSRs and sign them **with the Root**
- Generate per-intermediate CRLs
- Build chain files in `<pki-dir>/chain/<CA_NAME>.chain.pem`

Idempotent: if an Intermediate already has its cert, it is skipped.

### List Intermediates and status

```bash
./easypki.sh int --pki-dir ./pki --info
```

For each Intermediate:

- Subject / Issuer
- Validity
- Serial
- Fingerprint
- Key bits
- Status in Root DB (Valid / Revoked / Expired / Unknown)
- CRL info
- DB stats (valid/revoked/expired)
- Chain verification result

### Revoke an Intermediate CA

```bash
./easypki.sh int --pki-dir ./pki   --revoke-intermediate users   --reason keyCompromise
```

This:

- Revokes the Intermediate cert in the **Root** CA DB
- Regenerates the Root CRL

After that, issuing new certs from `users` via `cert` is **blocked**: the script checks that the Intermediate is still valid in the Root DB.

---

## Certificates (end-entity)

All cert operations are under the `cert` subcommand.

```bash
./easypki.sh cert [--pki-dir DIR] --ca <CA_NAME> <action> [options...]
```

### Issue a user/client certificate

```bash
./easypki.sh cert   --pki-dir ./pki   --ca apps   --issue-user alice   --days 365
```

This will:

- Use Intermediate `apps`
- Create `./pki/intermediates/apps/issued/alice/`
- Generate a **2048-bit RSA key** (unencrypted)
- Generate a CSR with `CN=alice`
- Sign it using the `usr_cert` profile (clientAuth)
- Create a `alice.fullchain.pem` if the CA chain exists

Resulting files:

```text
./pki/intermediates/apps/issued/alice/alice.key.pem
./pki/intermediates/apps/issued/alice/alice.csr.pem
./pki/intermediates/apps/issued/alice/alice.cert.pem
./pki/intermediates/apps/issued/apps/alice/alice.fullchain.pem
```

### Issue a server certificate (with SANs)

Basic example:

```bash
./easypki.sh cert   --pki-dir ./pki   --ca users   --issue-server api.homelab.lan   --days 825
```

With SANs (DNS and IP), you can repeat `--san`:

```bash
./easypki.sh cert   --pki-dir ./pki   --ca users   --issue-server web.homelab.lan   --days 825   --san "DNS:web.homelab.lan,IP:10.0.0.10"   --san "DNS:web.homelab.lan"   --san "IP:10.0.0.10"
```

Notes:

- `--issue-server` uses the `server_cert` profile (`serverAuth`).
- `--san` accepts:
  - `DNS:hostname`
  - `IP:ipaddress`
  - or bare hostnames (`example.com`) which are normalized to `DNS:example.com`.
- Duplicate SANs are deduplicated internally.

### Re-issue / replace a certificate

If a cert already exists for a given NAME under a CA:

- Re-running **without** `--replace` → **fails**.
- Re-running **with** `--replace`:
  - The existing certificate (if valid) is revoked in the CA DB
  - A new certificate is issued
  - The old `issued/<NAME>` directory is moved aside as `issued/<NAME>.revoked-<timestamp>`

Example:

```bash
# First issue
./easypki.sh cert --pki-dir ./pki --ca apps --issue-server replace-test.homelab.lan

# This will fail (already exists)
./easypki.sh cert --pki-dir ./pki --ca apps --issue-server replace-test.homelab.lan

# This will replace (revoke old, issue new)
./easypki.sh cert --pki-dir ./pki --ca apps --issue-server replace-test.homelab.lan --replace
```

### Revoke an end-entity certificate

```bash
./easypki.sh cert   --pki-dir ./pki   --ca apps   --revoke alice
```

The script:

- Looks under `issued/<NAME>/NAME.cert.pem`, or fallback under `certs/NAME.cert.pem`
- Revokes the cert using the Intermediate CA DB
- Regenerates the Intermediate CRL

Re-revoking the same NAME is considered an error and should fail.

### Generate CRLs

For one Intermediate CA:

```bash
./easypki.sh cert   --pki-dir ./pki   --ca apps   --crl
```

For **all** Intermediates:

```bash
./easypki.sh cert   --pki-dir ./pki   --crl
```

Intermediates revoked at the Root level are skipped when generating “all” CRLs.

### List certificates (CA DB view)

All Intermediates:

```bash
./easypki.sh cert --pki-dir ./pki --list
```

Specific Intermediate:

```bash
./easypki.sh cert --pki-dir ./pki --ca apps --list
```

Shows each DB entry with:

- Status code (`V`/`R`/`E`)
- Expiration / revocation date
- CN extracted from the DN

### Detailed info on one certificate

```bash
./easypki.sh cert   --pki-dir ./pki   --ca apps   --info alice
```

Outputs:

- Subject / Issuer
- Start / end date
- Serial
- SHA-256 fingerprint
- Status (VALID / REVOKED / EXPIRED / unknown)
- SANs (if present)
- Public key algorithm and bits
- Chain verification result (`Chain: OK` or `Chain: FAIL`)

---

## Security: passphrased vs unencrypted keys

**By default**, `easypki.sh` generates:

- **Root key**: encrypted (AES-256, passphrase prompted)
- **Intermediate keys**: unencrypted
- **End-entity keys**: unencrypted

### Test mode: no Root passphrase

For fully non-interactive testing, you can generate an **unencrypted Root key** via:

```bash
export EASYPKI_INSECURE_NO_PASSPHRASE=1

./easypki.sh root --pki-dir ./pki   --country FR   --state "Ile-de-France"   --locality "Paris"   --org "Homelab"   --root-cn "Homelab Root CA"
```

> ⚠️ **WARNING**: this is insecure and intended only for test / lab automation (like `test_easypki.sh`).  
> For anything remotely production-like, do **not** set this variable and keep the Root key encrypted and offline.

---

## Test suite

The test suite is `test_easypki.sh`. It:

- Creates **multiple PKI directories**:
  - `pki-main` (normal, used for most scenarios)
  - `pki-alt` (alternate Root)
  - `pki-broken` (corrupted root DB)
- Runs many **success** and **failure** tests:
  - Invalid parameters
  - Missing roots
  - Broken DB files
  - Massive Intermediate creation
  - Issuing many user and server certs
  - SAN normalization
  - Replace logic (`--replace`)
  - Revocations (end-entity + Intermediate CA)
  - CRL generation
  - External `openssl verify` checks

### Running the tests

From the repo:

```bash
./test_easypki.sh
```

You should see colored output like:

```text
[*] Using test workspace: /tmp/easypki-tests.XXXXXX
[*] easypki binary: ./easypki.sh
[*] Root key passphrase prompts are DISABLED in tests via EASYPKI_INSECURE_NO_PASSPHRASE=1

[*] TEST (expect failure): No subcommand should fail / show help
[OK] No subcommand should fail / show help
...
=======================================
Test summary:
  Passed: 99
  Total : 99
  RESULT: ALL TESTS PASSED 🎉
Logs for last command are in:
  /tmp/easypki-tests.XXXXXX/log.out
  /tmp/easypki-tests.XXXXXX/log.err
Workspace kept at: /tmp/easypki-tests.XXXXXX
```

Internally, the test suite:

- Uses `mktemp -d` to create a temporary workspace.
- Sets `EASYPKI_INSECURE_NO_PASSPHRASE=1` to avoid interactive Root passphrase prompts.
- Logs stdout/stderr of each test to `log.out` and `log.err` in that workspace.

### Environment variables for tests

- `EASYPKI`  
  Path to the `easypki` script to test (default: `./easypki.sh`).

  ```bash
  EASYPKI=/usr/local/bin/easypki ./test_easypki.sh
  ```

- `BASE_DIR`  
  Pre-set workspace directory (if you don’t want `mktemp`):

  ```bash
  BASE_DIR=/tmp/my-easypki-tests ./test_easypki.sh
  ```

- `EASYPKI_INSECURE_NO_PASSPHRASE=1`  
  Used by `easypki.sh` to generate an **unencrypted** Root key (test only).  
  The test script exports this by default.

---

## Example: full quickstart

1. **Create Root**

   ```bash
   ./easypki.sh root      --pki-dir ./pki      --country FR      --state "Ile-de-France"      --locality "Paris"      --org "Homelab"      --root-cn "Homelab Root CA"
   ```

2. **Create Intermediates**

   ```bash
   ./easypki.sh int --pki-dir ./pki      -i apps      -i users      --country FR      --state "Ile-de-France"      --locality "Paris"      --org "Homelab"      --int-cn-prefix "Homelab Intermediate CA - "
   ```

3. **Issue a client certificate for `alice`**

   ```bash
   ./easypki.sh cert      --pki-dir ./pki      --ca apps      --issue-user alice      --days 365
   ```

   Resulting key + cert + fullchain under:
   `./pki/intermediates/apps/issued/alice/`

4. **Issue a server cert for `web.homelab.lan` with SANs**

   ```bash
   ./easypki.sh cert      --pki-dir ./pki      --ca users      --issue-server web.homelab.lan      --days 825      --san "web.homelab.lan"      --san "DNS:web.homelab.lan,IP:10.0.0.10"
   ```

5. **Inspect / debug**

   ```bash
   ./easypki.sh root --pki-dir ./pki --info
   ./easypki.sh int  --pki-dir ./pki --info
   ./easypki.sh cert --pki-dir ./pki --ca apps --info alice
   ./easypki.sh cert --pki-dir ./pki --list
   ```

6. **Regenerate CRLs**

   ```bash
   ./easypki.sh cert --pki-dir ./pki --crl
   ```

---

## Backup and recovery

**You should back up the entire `<pki-dir>` directory**, especially:

- `root/private/ca.key.pem` (Root key)
- `root/certs/ca.cert.pem` (Root cert)
- `root/index.txt`, `serial`, `crlnumber`
- Each `intermediates/<CA_NAME>/private/intermediate.key.pem`
- Chains and issued directories if you want to preserve everything as-is

If the Root key is lost, you cannot revoke existing Intermediates or issue new ones.  
Treat it like any other CA: protect it carefully and make backups.

---

## Disclaimer

This is aimed at **homelab / lab / small internal setups**.  
It is **not** a full-featured enterprise PKI solution, and you should review and adapt it before using it in any serious or regulated environment.

That said, it gives you a transparent, scriptable, and easily auditable PKI layout based on `openssl` and plain files.

Enjoy 🔐
