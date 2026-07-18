# ZeroVaultID evidence bundle signing key

ZeroVaultID Cert Seal evidence bundles are signed with Ed25519 over the bundle
manifest. The authentic signing public-key fingerprint (SHA-256 of the SPKI DER
encoding of the public key) is:

    e84ce01d300fef9427c979174068bf3d95d27b3c9bdaf58f5f2a3f2094a0d0e9

Compute the same value from a bundle's manifest-pubkey.pem and compare (needs
OpenSSL 3.x):

    openssl pkey -pubin -in manifest-pubkey.pem -pubout -outform DER | openssl dgst -sha256

If it does not match the value above, the bundle was signed by someone other than
ZeroVaultID and must not be trusted even if its own verifier reports success.
