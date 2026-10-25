#!/usr/bin/env bash
# The by-hand recipe, Ed25519 half (ANCHOR-SIGN-DESIGN-v5.md section 11.3). It uses only bash, perl
# and openssl, never a tool ZeroVaultID ships. Run it in a NEW EMPTY folder of your own.
#
#   bash by-hand-ed25519.sh <anchor|history|key> <signed file> <its .sig.json> <anchor-signer.json> <your pinned key_id>
#
# Requirements: bash 4 or later, perl 5, and OpenSSL 3.x (it needs SHA3-256 and Ed25519 with -rawin).
# It does not use wc, so a BSD wc that pads its count cannot give a false result.
#
# Every check stops everything after it (set -euo pipefail plus an explicit exit on each failed
# comparison; a bare "[ ... ] && echo" would NOT stop a set -e script).
# Exit 0: the Ed25519 half verifies, and the file ed25519-half.pass is written LAST.
# Exit 1: a check refused (LENGTHS, KEY-ID-MISMATCH, DIGEST, PREIMAGE-LENGTH, or openssl's
#         "Signature Verification Failure").
# Exit 2: the recipe could not run (USAGE, KIND, PIN-FORMAT, REQUIREMENT, INPUT-MISSING, NOT-EMPTY).
# Both halves must pass. mldsa-half.mjs refuses to run in a folder without ed25519-half.pass for the
# same preimage AND the same ML-DSA-87 public-key file (v5, A3-2): the pass record binds the sha256 of
# mldsa87.pk.hex, the key this script took from the key file whose key_id equals your pin.
set -euo pipefail
[ "$#" -eq 5 ] || { echo "FAIL: USAGE"; exit 2; }
KIND=$1 F=$2 S=$3 KF=$4 KEY_ID=$5
case "$KIND" in
  anchor)  P='talon-anchor:v1:';         L=163 ;;
  history) P='talon-anchor-history:v1:'; L=171 ;;
  key)     P='talon-anchor-key:v1:';     L=167 ;;
  *) echo "FAIL: KIND"; exit 2 ;;
esac
[[ "$KEY_ID" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: PIN-FORMAT (64 lowercase hex)"; exit 2; }
OV=$(openssl version)
[[ "$OV" =~ ^OpenSSL\ 3\. ]] || { echo "FAIL: REQUIREMENT (OpenSSL 3.x is needed)"; exit 2; }
for x in "$F" "$S" "$KF"; do
  [ -f "$x" ] && [ -r "$x" ] || { echo "FAIL: INPUT-MISSING ($x cannot be read)"; exit 2; }
done
ENTRIES=$(ls -A .)
[ -z "$ENTRIES" ] || { echo "FAIL: NOT-EMPTY (this folder is not empty; use a new empty folder)"; exit 2; }

# 1. Take the hex values out of the key file and the sidecar, and check their lengths.
perl -0ne 'print $1 if /"ed25519_spki_der": "([0-9a-f]{88})"/' "$KF" > ed25519.spki.hex
perl -0ne 'print $1 if /"mldsa87_pk": "([0-9a-f]{5184})"/' "$KF" > mldsa87.pk.hex
perl -0ne 'print $1 if /"ed25519": "([0-9a-f]{128})"/' "$S" > ed25519.sig.hex
perl -0ne 'print $1 if /"mldsa87": "([0-9a-f]{9254})"/' "$S" > mldsa87.sig.hex
ED_SPKI=$(cat ed25519.spki.hex); ML_PK=$(cat mldsa87.pk.hex); ED_SIG=$(cat ed25519.sig.hex); ML_SIG=$(cat mldsa87.sig.hex)
[ "${#ED_SPKI} ${#ML_PK} ${#ED_SIG} ${#ML_SIG}" = "88 5184 128 9254" ] || { echo "FAIL: LENGTHS"; exit 1; }
echo "LENGTHS-OK"

# 2. Recompute the key_id from BOTH public keys in the key file. All 64 characters must equal your pin.
K=$(printf '{"alg":"ed25519+ml-dsa-87","ed25519":"%s","mldsa87":"%s"}' "$ED_SPKI" "$ML_PK" \
    | openssl dgst -sha3-256 -r | cut -c1-64)
[ "$K" = "$KEY_ID" ] || { echo "FAIL: KEY-ID-MISMATCH (the key file's two keys commit to a different key_id)"; exit 1; }
echo "KEY-ID-MATCH $K"

# 3. Rebuild the preimage from the signed file's own bytes and your pin.
D=$(openssl dgst -sha3-256 -r "$F" | cut -c1-64)
[[ "$D" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: DIGEST"; exit 1; }
printf '%sed25519+ml-dsa-87:%s:%s' "$P" "$KEY_ID" "$D" > preimage.bin
PRE=$(cat preimage.bin)
[ "${#PRE}" = "$L" ] || { echo "FAIL: PREIMAGE-LENGTH"; exit 1; }

# 4. Verify the Ed25519 half with openssl alone. A failure prints "Signature Verification Failure" and exits 1.
perl -ne 'chomp; print pack("H*", $_)' ed25519.spki.hex > ed25519.spki.der
perl -ne 'chomp; print pack("H*", $_)' ed25519.sig.hex > ed25519.sig
openssl pkeyutl -verify -pubin -keyform DER -inkey ed25519.spki.der -rawin -in preimage.bin -sigfile ed25519.sig

# 5. Record the pass for the ML-DSA-87 half, last: the kind, the length, the sha256 of this preimage and
#    (v5, A3-2) the sha256 of mldsa87.pk.hex, the ML-DSA-87 key bound to your pin in step 2.
PD=$(openssl dgst -sha256 -r preimage.bin | cut -c1-64)
[[ "$PD" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: DIGEST"; exit 1; }
MD=$(openssl dgst -sha256 -r mldsa87.pk.hex | cut -c1-64)
[[ "$MD" =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: DIGEST"; exit 1; }
printf 'ED25519-HALF-PASS %s %s %s %s\n' "$KIND" "$L" "$PD" "$MD" > ed25519-half.pass
echo "ED25519-HALF-PASS preimage $L octets"
