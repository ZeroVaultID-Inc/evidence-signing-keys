# TALON anchor history

This table shows the rows of HISTORY.json in this folder, with dates written month/day/year. HISTORY.json is the authoritative file; if this table and HISTORY.json ever differ, HISTORY.json governs.

| Entry | Anchor date | Valid until (00:00 UTC) | SHA-256 | SHA3-256 | Signed by key_id | First published (UTC date) | Status | Note |
|---|---|---|---|---|---|---|---|---|
| 0 | 10/01/2026 | 10/31/2026 | b8a7f3201546443920c5fd3720a94313f6b6aecf68ec87b808ae1916c2379248 | 303308693e7559e622ae04f5a637c9c65f213a7891559702a542f400892121a3 | none | 10/25/2026 | superseded | unsigned |
| 1 | 10/22/2026 | 11/21/2026 | 82ef0ef4f54cabfb2586b34da0f50378345b43710f2aca8b215ba4dad21a9e3a | 84d3f711acb5dbab987b5bb588f9983f5fa4161265af29031ab612d41e6cefbb | c92e191497a9436514b33b4a45336111e21d47bfcd33cdfe694fb7d9028c2c7a | 10/25/2026 | current | signed |

"Valid until" is the anchor's next_update; the TALON verifier refuses to check an object against the anchor once its clock passes 00:00 UTC on that date.

"unsigned" on entry 0 means only that the anchor of 10/01/2026 carries no signature.

Entry 1 is signed in anchors/2026-10-22/anchor-snapshot.json.sig.json, whose SHA-256, 965c2124ee133c2a84836703cc07903404fdb38bc1bb7c7d7e8988465211d0d8, is sig_sha256 in HISTORY.json.
