// mldsa-half.mjs: the by-hand recipe, ML-DSA-87 half (ANCHOR-SIGN-DESIGN-v5.md section 11.3; PLAN advisory A3).
// It loads ML-DSA-87 from YOUR OWN pinned copy of the talon-verify bundle (the vendored
// @noble/post-quantum 0.6.1), never from anything published beside the anchor. Run it in the same
// folder, after by-hand-ed25519.sh printed ED25519-HALF-PASS (that run wrote preimage.bin from
// your pinned key_id, mldsa87.pk.hex, mldsa87.sig.hex and, last, ed25519-half.pass).
//
//   node mldsa-half.mjs <your talon-verify bundle dir> preimage.bin mldsa87.pk.hex mldsa87.sig.hex
//
// Exit 0 and MLDSA87-HALF-PASS: the signature verifies, pure ML-DSA-87, empty context.
// Exit 1 and MLDSA87-HALF-FAIL: it does not; or an input has the wrong shape; or the Ed25519 half
//        has not passed for this same preimage in this folder (no ed25519-half.pass, or one for
//        another preimage); or (v5, A3-2) the public-key file named on the command line is not the
//        one the Ed25519 half took from the key file and bound to your pin. Both halves must pass.
// Exit 2 and MLDSA87-HALF-ERROR: the run could not proceed (usage, an input that cannot be read,
//        the library could not be loaded, or it threw). Never read as a verdict.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { pathToFileURL } from "node:url";

const stop = (code, msg) => { console.log(msg); process.exit(code); };
const [bundle, preFile, pkFile, sigFile, extra] = process.argv.slice(2);
if (!bundle || !preFile || !pkFile || !sigFile || extra !== undefined) stop(2, "MLDSA87-HALF-ERROR usage");
const lib = join(bundle, "vendor/node_modules/@noble/post-quantum/ml-dsa.js");
let ml_dsa87;
try { ({ ml_dsa87 } = await import(pathToFileURL(lib).href)); } catch { stop(2, "MLDSA87-HALF-ERROR the library could not be loaded"); }
if (!ml_dsa87 || typeof ml_dsa87.verify !== "function") stop(2, "MLDSA87-HALF-ERROR the library could not be loaded");
let libDigest;
try { libDigest = createHash("sha256").update(readFileSync(lib)).digest("hex"); } catch { stop(2, "MLDSA87-HALF-ERROR the library could not be loaded"); }
console.log(`library ml-dsa.js sha256 ${libDigest} (compare with your pinned bundle's manifest)`);
const read = (f) => { try { return readFileSync(f); } catch { return stop(2, `MLDSA87-HALF-ERROR cannot read ${f}`); } };
const preBuf = read(preFile), pkBuf = read(pkFile), sigBuf = read(sigFile);

// Both halves must pass: the Ed25519 half's pass record for this exact preimage and this exact
// ML-DSA-87 public-key file, in the same folder.
const markerFile = join(dirname(preFile), "ed25519-half.pass");
let marker;
try { marker = readFileSync(markerFile, "ascii"); } catch { stop(1, "MLDSA87-HALF-FAIL no ed25519-half.pass in this folder: the Ed25519 half has not passed"); }
const m = /^ED25519-HALF-PASS (anchor|history|key) (163|171|167) ([0-9a-f]{64}) ([0-9a-f]{64})\n$/.exec(marker);
const sha = (b) => createHash("sha256").update(b).digest("hex");
if (!m || Number(m[2]) !== preBuf.length || m[3] !== sha(preBuf)) stop(1, "MLDSA87-HALF-FAIL ed25519-half.pass is not for this preimage");
if (m[4] !== sha(pkBuf)) stop(1, "MLDSA87-HALF-FAIL the public-key file is not the one the Ed25519 half bound to your pin");

const hex = (buf, name, n) => { const t = buf.toString("latin1"); if (!new RegExp(`^[0-9a-f]{${n}}$`).test(t)) stop(1, `MLDSA87-HALF-FAIL ${name} is not ${n} lowercase hex characters`); return Buffer.from(t, "hex"); };
const pk = hex(pkBuf, pkFile, 5184), sig = hex(sigBuf, sigFile, 9254);
if (![163, 167, 171].includes(preBuf.length) || !/^talon-anchor(-history|-key)?:v1:ed25519\+ml-dsa-87:[0-9a-f]{64}:[0-9a-f]{64}$/.test(preBuf.toString("latin1"))) stop(1, "MLDSA87-HALF-FAIL preimage shape");
let ok;
try { ok = ml_dsa87.verify(new Uint8Array(sig), new Uint8Array(preBuf), new Uint8Array(pk)); } catch { stop(2, "MLDSA87-HALF-ERROR the library threw"); }
if (ok !== true) stop(1, "MLDSA87-HALF-FAIL Signature Verification Failure");
stop(0, `MLDSA87-HALF-PASS preimage ${preBuf.length} octets`);
