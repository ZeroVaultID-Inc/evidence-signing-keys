# ZeroVaultID evidence bundle signing key

ZeroVaultID Cert Seal evidence bundles are signed with Ed25519 over the bundle
manifest. The authentic signing public-key fingerprint (SHA-256 of the SPKI DER
encoding of the public key) is:

    234374010ba7c648e59f26003b7915ce2c70899cd101c770cb046f5d6e3b5286

Rotated 2026-08-16. This is the only fingerprint that authenticates a ZeroVaultID
Cert Seal evidence bundle.

Compute the same value from a bundle's manifest-pubkey.pem and compare (needs
OpenSSL 3.x):

    openssl pkey -pubin -in manifest-pubkey.pem -pubout -outform DER | openssl dgst -sha256

If it does not match the value above, the bundle was signed by someone other than
ZeroVaultID and must not be trusted even if its own verifier reports success.

## Current kit

    fe876ce644321c2f22b3cd2c565b25ea6c5452912dfdc905a100f31b49e3efac
    zerovaultid-certseal-rung6.zip, 4510686 bytes

PUBLISHED 2026-08-16. The bundle inside this archive is sealed under the
fingerprint above. It is served at zerovaultid.com/certseal and it replaces the
superseded archive listed below.

Confirm the digest before extracting:

    sha256sum zerovaultid-certseal-rung6.zip

The file name is identical to the superseded archive's, so the digest and the
byte count are the only things that tell them apart. Matching this digest
establishes that you hold the published file and nothing more; the key
fingerprint above is still what establishes authenticity.

## Revoked keys

    e84ce01d300fef9427c979174068bf3d95d27b3c9bdaf58f5f2a3f2094a0d0e9

REVOKED 2026-08-16. Private key exposure confirmed; the exposure predates this
entry and its start date is not established.

RETROACTIVE INVALIDATION, read this before verifying anything. Any bundle whose
manifest-pubkey.pem carries this fingerprint is untrusted, regardless of whether
its signature verifies. A valid signature under a revoked key proves only that
whoever produced the bundle held the private key, and that is no longer a
property unique to ZeroVaultID. This revocation is not scoped to bundles
published after a date: it applies to every bundle ever signed under this key,
including bundles you may already hold and may have verified successfully in the
past. Re-verify against
234374010ba7c648e59f26003b7915ce2c70899cd101c770cb046f5d6e3b5286 or discard.

## Dead artifacts

    3766af451d3fcb54698b35130044c80182bb3444d8ffc61e66d3f17749f51ef4
    zerovaultid-certseal-rung6.zip, 4510072 bytes

SUPERSEDED 2026-08-16. This archive is signed under the revoked key above. Do
not distribute it and do not treat a successful `node verify.js` run against it
as evidence of anything. It is replaced by the archive listed under Current kit
above, published at zerovaultid.com/certseal.

## TALON anchor-signing key: a second, separate key, for TALON trust anchors and their history (not for Cert Seal evidence bundles)

This section and the folder talon-anchor/ concern a second key, the TALON anchor-signing key, which signs TALON trust anchors, the TALON anchor history and TALON anchor-key statements only and does not authenticate Cert Seal evidence bundles.

The Cert Seal key and every line above this section are unchanged by this section.

Dates in this section are written month/day/year; dates inside the files keep the form YYYY-MM-DD.

A TALON trust anchor, anchor-snapshot.json, is the list of keys that the TALON verifier, verify.mjs, reads and accepts. It is the verifier's trust root, so you obtain it from outside any TALON bundle.

No version of verify.mjs released before this anchor checks anchor signatures, so check the anchor with the steps in this section before you give it to verify.mjs.

### The key

- Key file: talon-anchor/anchor-signer.json. Key ID (key_id, the SHA3-256 commitment to both public keys): c92e191497a9436514b33b4a45336111e21d47bfcd33cdfe694fb7d9028c2c7a
- Algorithms: Ed25519 and ML-DSA-87 together (alg "Ed25519+ML-DSA-87").
- valid_from: 2026-10-18, the UTC date on which the two keys were created (10/18/2026).
- rotate_by: 2027-10-01, the date by which the key is due to be replaced (10/01/2027).
- status: active.
- SHA-256 of anchor-signer.json: 99eaa97bd76f05ed1fb832c61ec9d1e20102232725727281f1f654a7deca685c
- birth_record: 8bd8524932b28d1344ee18b091bd2d77d0441a2abf4ec73b580d173c123b10ce, the SHA-256 of talon-anchor/BIRTH-RECORD.md.

Accept a signature by this key only when both halves, Ed25519 and ML-DSA-87, verify.

BIRTH-RECORD.md lists, for each of the two keys, its creation time in UTC, key spec, key usage, origin and region, taken from the cloud provider's creation records, and the SHA-256 of each public key.

Those records are copies that ZeroVaultID downloaded; they carry no signature from the cloud provider, so the birth record rests on ZeroVaultID's word.

The key file comes with an announce statement, talon-anchor/statements/2026-10-22-announce.json, signed by this key with both halves in the .sig.json file beside it. It shows only that the holder of the key published this key file; it does not replace comparing the key in this repository and on the ZeroVaultID website.

### The current anchor

- File: talon-anchor/anchors/2026-10-22/anchor-snapshot.json
- snapshot_taken: 2026-10-22; next_update: 2026-11-21
- SHA-256: 82ef0ef4f54cabfb2586b34da0f50378345b43710f2aca8b215ba4dad21a9e3a
- SHA3-256: 84d3f711acb5dbab987b5bb588f9983f5fa4161265af29031ab612d41e6cefbb

This anchor is signed by the TALON anchor-signing key, both halves, in the .sig.json file beside it (SHA-256 965c2124ee133c2a84836703cc07903404fdb38bc1bb7c7d7e8988465211d0d8).

### Which anchor to use

The previous anchor, talon-anchor/anchors/2026-10-01/anchor-snapshot.json, stays valid until 00:00 UTC on 10/31/2026, which is 8:00 PM EDT Friday 10/30/2026.

The current anchor is valid from 00:00 UTC on 10/22/2026 until 00:00 UTC on 11/21/2026, which is 7:00 PM EST Friday 11/20/2026, 30 days after its snapshot_taken.

Both anchors are valid together until the previous one lapses.

After that, use the current anchor, or a later anchor once it is listed in HISTORY.json here and on the ZeroVaultID website.

The TALON verifier refuses to check an object against an anchor once its clock passes the anchor's next_update.

### Anchor history

talon-anchor/HISTORY.json lists, in order, the TALON trust anchors kept in talon-anchor/, starting with the anchor of 10/01/2026; each entry is chained to the one before it by prev_entry_sha256. talon-anchor/HISTORY.md shows the same rows with dates written month/day/year.

HISTORY.json is signed by the TALON anchor-signing key, both halves, in HISTORY.json.sig.json.

- Entry 0: the anchor of 10/01/2026, status superseded, note "unsigned", first published on 10/25/2026 (a UTC date).
- Entry 1: the current anchor, status current, note "signed", first published on 10/25/2026 (a UTC date).

The history of this repository can be rewritten by whoever controls it.

Compare HISTORY.json here with the copy on the ZeroVaultID website, and with any web-archive copy you hold, before you rely on it.

### Where else these files are

Compare these files with the copies on the ZeroVaultID website, at https://zerovaultid.com/talon-anchor/, and use them only if they agree.

### How to check the key before you use it

1. Download anchor-signer.json from this folder on the default branch and from the ZeroVaultID website at https://zerovaultid.com/talon-anchor/; if the website names a commit of this repository, download it at that commit too. All copies must have the same SHA-256. The default branch also shows a later revocation, which a pinned commit cannot.
2. Check the SHA-256 of check-anchor.mjs, anchor-common.mjs, kat/KAT-VECTORS-v3.json, by-hand-ed25519.sh and mldsa-half.mjs against talon-anchor/SHA256SUMS here and on the website. check-anchor.mjs runs only with anchor-common.mjs and kat/KAT-VECTORS-v3.json beside it, so compare all three, not check-anchor.mjs alone.
3. Recompute the key_id from the two public keys in the key file and compare all 64 characters with the key ID above. With perl and OpenSSL 3.x, in the folder holding your copy of anchor-signer.json, run:

   ```
   ED=$(perl -ne 'print $1 if /"ed25519_spki_der": "([0-9a-f]+)"/' anchor-signer.json)
   ML=$(perl -ne 'print $1 if /"mldsa87_pk": "([0-9a-f]+)"/' anchor-signer.json)
   echo "${#ED} ${#ML}"
   printf '{"alg":"ed25519+ml-dsa-87","ed25519":"%s","mldsa87":"%s"}' "$ED" "$ML" | openssl dgst -sha3-256 -r | cut -c1-64
   ```

   The third line must print 88 5184; if it prints anything else, your copy is not in the published form, so do not use it. The last line prints the key_id.

4. As a second view only, run this in the same folder, with your copies of check-anchor.mjs, anchor-common.mjs and kat/KAT-VECTORS-v3.json there, placed as in talon-anchor/:

   ```
   node check-anchor.mjs --noble <YOUR_TALON_VERIFY_BUNDLE_DIR>/vendor/node_modules/@noble --print-key-id anchor-signer.json
   ```

   Never let it be your only check.

Accept the key only if every copy agrees and the key_id you recomputed equals the key ID shown here and on the website. If anything differs, or either copy cannot be read, do not use the key. Do not pick the majority.

You may also compare with web-archive copies of this repository page and of the website page.

### How to check the current anchor

by-hand-ed25519.sh needs bash 4 or later, perl 5 and OpenSSL 3.x; mldsa-half.mjs needs node 20 and your own pinned copy of the TALON verifier bundle. check-anchor.mjs needs node 20 exactly (it refuses any other major version), anchor-common.mjs and kat/KAT-VECTORS-v3.json beside it as in talon-anchor/, and --noble set to the folder vendor/node_modules/@noble inside your own pinned copy of the TALON verifier bundle.

kat/KAT-VECTORS-v3.json holds two test keys, each made from a public recipe written in that file, for testing only. Both are test keys never used for anything real, and no TALON checker trusts either. The main test key, with an Ed25519 half and an ML-DSA-87 half, is a deny-listed test key: check-anchor.mjs refuses a key file that holds it, or either of its halves, because they are on its deny list. The second test key, an Ed25519 key, is not on that list; check-anchor.mjs refuses anything signed with it in place of the TALON anchor-signing key, because no key file that holds it has the key ID of the TALON anchor-signing key, which check-anchor.mjs pins.

Make a new, empty folder, change into it, and run the two halves with the paths to your downloaded copies (`<DL>` below is the folder into which you downloaded the current anchor's files and anchor-signer.json):

```
bash <DL>/by-hand-ed25519.sh anchor <DL>/anchor-snapshot.json <DL>/anchor-snapshot.json.sig.json <DL>/anchor-signer.json <YOUR_PINNED_KEY_ID>
node <DL>/mldsa-half.mjs <YOUR_TALON_VERIFY_BUNDLE_DIR> preimage.bin mldsa87.pk.hex mldsa87.sig.hex
```

Both halves must pass: ED25519-HALF-PASS, then MLDSA87-HALF-PASS.

Then, with anchor-common.mjs and kat/KAT-VECTORS-v3.json in `<DL>` beside check-anchor.mjs, as in talon-anchor/, run:

```
node <DL>/check-anchor.mjs --noble <YOUR_TALON_VERIFY_BUNDLE_DIR>/vendor/node_modules/@noble --kind anchor --file <DL>/anchor-snapshot.json --sig <DL>/anchor-snapshot.json.sig.json --key-file <DL>/anchor-signer.json --expect-key-id <YOUR_PINNED_KEY_ID>
```

Its last line must begin CHECK-ANCHOR PASS.

The same scripts check HISTORY.json (kind history) and the announce statement (kind key, with --statement-kind announce and --anchor).

Only then give the anchor to verify.mjs with --anchor.

### Files in talon-anchor/

- anchor-signer.json
- BIRTH-RECORD.md
- HISTORY.json
- HISTORY.json.sig.json
- HISTORY.md
- anchors/2026-10-01/anchor-snapshot.json
- anchors/2026-10-22/anchor-snapshot.json
- anchors/2026-10-22/anchor-snapshot.json.sig.json
- statements/2026-10-22-announce.json
- statements/2026-10-22-announce.json.sig.json
- check-anchor.mjs
- anchor-common.mjs
- kat/KAT-VECTORS-v3.json
- by-hand-ed25519.sh
- mldsa-half.mjs
- SHA256SUMS

talon-anchor/SHA256SUMS lists the SHA-256 of every other file in talon-anchor/.

### If this key is replaced or revoked

ZeroVaultID replaces this key by its rotate_by date, or earlier on any doubt. A planned replacement is announced in this section and on the ZeroVaultID website at least 30 days before the new key signs its first anchor, with a statement signed by both the old and the new key.

If this key is revoked, a notice appears at the top of this section and at the top of the website's key page. Act on a revocation seen in either place; a revocation needs no signature to be honored.

Notices about this key appear only in this section and on the ZeroVaultID website.
