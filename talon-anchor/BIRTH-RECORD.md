# TALON anchor signing key: birth record

This file records how the two halves of the TALON anchor signing key were created. The values come from the AWS CloudTrail CreateKey records of 10/18/2026, as ZeroVaultID downloaded them, and from the two public keys that AWS KMS returned to ZeroVaultID by GetPublicKey on 10/22/2026 UTC (the evening of 10/21/2026 in New York, EDT). All times are UTC.

key_id: c92e191497a9436514b33b4a45336111e21d47bfcd33cdfe694fb7d9028c2c7a

The key_id is the SHA3-256 commitment of the two public keys. It is the key_id in anchor-signer.json.

| | Ed25519 half | ML-DSA-87 half |
|---|---|---|
| Key spec | ECC_NIST_EDWARDS25519 | ML_DSA_87 |
| Key usage | SIGN_VERIFY | SIGN_VERIFY |
| Origin | AWS_KMS | AWS_KMS |
| Region | us-east-1, single-Region | us-east-1, single-Region |
| Creation time (the key's creationDate in the CreateKey record) | 2026-10-18T22:31:16Z | 2026-10-18T22:36:25Z |
| CreateKey event time | 2026-10-18T22:31:16Z | 2026-10-18T22:36:26Z |
| SHA-256 of the public key as KMS returned it (SubjectPublicKeyInfo, DER) | 934049479762ccf45b2be2a833e7dd8ecc25eb62186141c6500385b386983dd0 | 78e0580b779b22bcb333f6f89ad089297d5f3eb76b042154d749c2facebe764a |
| SHA-256 of the public key as anchor-signer.json holds it | 934049479762ccf45b2be2a833e7dd8ecc25eb62186141c6500385b386983dd0 (ed25519_spki_der is the DER itself) | fb24dab9129987a5b39a744a4f849a1c415576fb83f5c5b1457980389e709a5a (mldsa87_pk, the DER without its 22-octet header) |

Limits:
- These CloudTrail records are copies that ZeroVaultID downloaded, and the GetPublicKey answers were saved by ZeroVaultID. Neither carries a signature from AWS, so this birth record rests on ZeroVaultID's word.
- No screenshot of the key setup is part of this record. The CloudTrail records above take its place.
- This file holds no KMS key id, ARN, account number or MFA identifier.
