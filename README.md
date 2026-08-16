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
