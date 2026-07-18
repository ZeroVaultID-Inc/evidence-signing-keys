# ZeroVaultID evidence bundle signing key

ZeroVaultID Cert Seal evidence bundles are signed with Ed25519 over the bundle
manifest. The authentic signing public-key fingerprint (SHA-256 of the SPKI DER
encoding of the public key) is:

    e84ce01d300fef9427c979174068bf3d95d27b3c9bdaf58f5f2a3f2094a0d0e9

Its 16-hex prefix e84ce01d300fef94 appears in earlier references and is simply the
first 16 hex characters of the full value above; both identify the same key.

The bundle verifier prints the fingerprint of the key it verified against. A
reviewer must match the printed value against the fingerprint published here. A
mismatch means the bundle was signed by someone other than ZeroVaultID and must
not be trusted even if every other check passes.
