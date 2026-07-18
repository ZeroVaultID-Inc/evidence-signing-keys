# ZeroVaultID evidence bundle signing key

ZeroVaultID Cert Seal evidence bundles are signed with Ed25519 over the bundle
manifest. The authentic signing public-key fingerprint is:

    e84ce01d300fef94

The bundle verifier prints the fingerprint of the key it verified against. A
reviewer must match the printed value against the fingerprint published here. A
mismatch means the bundle was signed by someone other than ZeroVaultID and must
not be trusted even if every other check passes.
