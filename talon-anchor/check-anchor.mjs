// check-anchor.mjs: the standalone checker for the TALON trust anchor, its history and its key statements
// (ANCHOR-SIGN-DESIGN-v7.md section 5; v2 section 5, kept, with v3's A-6, A-7, A-8, A-9 and the history rules).
//
//   node check-anchor.mjs --kind anchor  --file <anchor> --sig <anchor>.sig.json --key-file <anchor-signer.json> [--expect-key-id <hex>] [--clock <ISO instant>]
//   node check-anchor.mjs --kind history --file HISTORY.json --sig HISTORY.json.sig.json --key-file <...> [--previous <older HISTORY.json>] [--anchors-dir <dir>]
//   node check-anchor.mjs --kind key --statement-kind announce --file <statement> --sig <statement>.sig.json --key-file <...> --anchor <the anchor it accompanies> [--history <HISTORY.json>]
//   node check-anchor.mjs --kind key --statement-kind rotate|revoke --file <statement> --sig <...> --key-file <...> [--new-key-file <f> --new-sig <f>]
//   node check-anchor.mjs --print-key-id <anchor-signer.json>
//   (each also takes --noble <dir>: the vendored @noble folder; default ../talon-verify/vendor/node_modules/@noble
//    beside this file, the layout of the repository's tools/ folder)
//
// Offline. Reads only the files named; node built-ins plus the vendored @noble/post-quantum, refused unless the
// three @noble trees hash to their pins; writes nothing; no network; reads no environment variable.
// Checks, in order, each stopping everything after it (v7 5.4): CA-0 start-up (exit 2), CA-1 invocation (exit 2),
// PIN-DISAGREES (exit 2), CA-2 key file shape, CA-3 key_id recomputes, CA-4 deny list, CA-5 pin, CA-6 sidecar
// shape, CA-7 display fields, CA-8 both signatures (a library throw is exit 2), CA-9 the document by kind, CA-10 the
// dates of an anchor against the clock (D-FUTURE exit 1, D-EXPIRED exit 2). Exit 0 PASS, 1 artifact fail, 2 could
// not run or configuration disagrees. PASS: last line `CHECK-ANCHOR PASS kind=... key_id=... file_sha256=...
// file_sha3_256=...`; FAIL: last line `CHECK-ANCHOR FAIL <check id>: <fixed message>`.
//
// THE TRUST LIMIT (v7 section 1): a forger who replaces the anchor can also replace a check-anchor.mjs published
// beside it. This checker is never the backstop; the relying party's own pinned key_id and the by-hand recipe are.
//
// THE CONTROL SEAM: the CLI entry passes the module-private ANCHOR_SIGNER_KEY_ID by name at its one call site of
// checkAnchorCore (CAC-25 asserts this by reading this source). The controls call the core with throwaway pins.
import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as C from "./anchor-common.mjs";

// v7 5.2: written UNSET-UNTIL-T16 by the build; the real key_id is written after T16 as its own reviewed one-line
// change. Until then CA-0 refuses every run (exit 2), so a checker with no key can never pass anything.
const ANCHOR_SIGNER_KEY_ID = "c92e191497a9436514b33b4a45336111e21d47bfcd33cdfe694fb7d9028c2c7a";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_NOBLE_DIR = join(SELF_DIR, "..", "talon-verify", "vendor", "node_modules", "@noble");
export const DEFAULT_KAT_PATH = join(SELF_DIR, "kat", "KAT-VECTORS-v3.json");
// design v3's kat/v3/KAT-VECTORS-v3.json (v7 2.6), pinned.
export const KAT_SHA256 = "434b3cb8b1f3d42339cb1e927bcb6d9041bffe5c018ee2bb1e97188380696b4c";

// The three vendored @noble trees: tool M's pins (mint-run-object-kms.mjs:110-115 at 8105b40), the values of
// tools/talon-verify/MANIFEST.json. Recipe: talon-verify lib/treehash.mjs (T-V1).
export const NOBLE_TREES = Object.freeze({
  "post-quantum": "05cf37191deace3effc5fffb5730b00a2af2ed7c4d392ded9e36b731921ac252",
  hashes: "4d5c452273b2684f428e9c785ec24c8435e81954c8b6b7b48d70d96e7f94a757",
  curves: "4be0b0addabf7e758fabae8afa55ca0960dff134824cb460c23c132055824393",
});

// v7 5.3: copied from design v3's kat/DENY-CONSTANTS-v3.json (sha256 047293b6...); control CAC-DENY recomputes each
// value from its source.
export const DENY = Object.freeze({
  KEY_IDS: Object.freeze([
    "eda05b56e3e990ffe28c8241d40bc1ca3b1b8d732bee9a1c32f03e5f3908151a", // release (zvid-release)
    "892f33e19c993d7010b0b565929bc09c3f59b95367a8c95616556cb773052c7b", // clearance (zvid-talon)
    "aa1f07cdb009c51b0929ec4caefba3b81f810ca9dcc3297900932efba08403f9", // dev (talon-dev)
    "0167d6d0021b07ead3971d71d19e3b537e2869741bdff76e1ebc58fce1c3dbd7", // KAT test key
  ]),
  ED25519_SPKI_SHA256: Object.freeze([
    "450cd7ad6d7df3db487f5d77a31d2abe5b596453a7a22339af2010bacba145d9", // release
    "8021c7bc4c24e1b56ee209c8371d5603486aea6c062ba3bb85951a0ed3bdec45", // clearance
    "0764d039a0152ae59fb56b101b5104928b7da848f74db05e735e9f5569b19647", // dev
    "10bcbe79cc4d6ffcf9b3bb298740f8aa607b06796246a9705ea28432033d559a", // KAT
    "e84ce01d300fef9427c979174068bf3d95d27b3c9bdaf58f5f2a3f2094a0d0e9", // revoked Rung 6 Cert Seal key (d3bcc53)
    "234374010ba7c648e59f26003b7915ce2c70899cd101c770cb046f5d6e3b5286", // current Cert Seal key (22be7b8)
  ]),
  MLDSA87_RAW_SHA256: Object.freeze([
    "2d1046030d3f064a824d98ee3e2eed45cf66a36eda30eaea7d33aa6dfe29b5fa", // release
    "f6bbab71aba2c84959d6e166123c1a6f0797d652a0dfa60a1d0933cd15c73fac", // clearance
    "78bae06666440b647d04c17034fbebe8f68fbbccbe35976be93ee1ff51607c7a", // dev
    "c519a0fb0436bf4599d54c301f980062cef1b4f861ce663b45c8e82d98b7b727", // KAT
  ]),
});

// v7 2.9: the announce text, exactly; and the members of each statement kind, in order (v2 2.9).
export const ANNOUNCE_TEXT =
  "This key signs TALON trust anchors, the TALON anchor history and TALON anchor-key statements only. It does not authenticate Cert Seal evidence bundles.";
export const STATEMENT_MEMBERS = Object.freeze({
  announce: Object.freeze(["statement", "version", "kind", "key_id", "key_file_sha256", "key_file_sha3_256", "date", "text"]),
  rotate: Object.freeze(["statement", "version", "kind", "old_key_id", "new_key_id", "new_key_file_sha256", "effective_date", "last_anchor_sha256_by_old_key", "date", "text"]),
  revoke: Object.freeze(["statement", "version", "kind", "key_id", "compromise_point", "last_trusted_anchor_sha256", "date", "text"]),
});
export const STATEMENT_KINDS = Object.freeze(["announce", "rotate", "revoke"]);
export const KINDS = Object.freeze(["anchor", "history", "key"]);

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const sha3 = (b) => createHash("sha3-256").update(b).digest("hex");

// ------------------------------------------------------------------ the tree hash (talon-verify lib/treehash.mjs)
function cSort(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
export function treeHash(baseDir, pkg) {
  const files = [];
  const walk = (rel) => {
    for (const name of readdirSync(join(baseDir, rel))) {
      const childRel = rel + "/" + name;
      const st = lstatSync(join(baseDir, childRel));
      if (st.isDirectory()) walk(childRel);
      else if (st.isFile()) files.push(childRel);
    }
  };
  walk(pkg);
  files.sort(cSort);
  const outer = createHash("sha256");
  for (const rel of files) outer.update(Buffer.from(sha256(readFileSync(join(baseDir, rel))) + "  " + rel + "\n", "utf8"));
  return outer.digest("hex");
}
// The three trees measured BEFORE anything is imported from them; then ml-dsa.js is imported from the measured tree.
export async function loadNoble(nobleDir) {
  try {
    if (!lstatSync(nobleDir).isDirectory()) return { ok: false };
    for (const pkg of Object.keys(NOBLE_TREES)) if (treeHash(nobleDir, pkg) !== NOBLE_TREES[pkg]) return { ok: false };
    const mod = await import(pathToFileURL(join(nobleDir, "post-quantum", "ml-dsa.js")).href);
    if (!mod || !mod.ml_dsa87 || typeof mod.ml_dsa87.verify !== "function") return { ok: false };
    return { ok: true, ml_dsa87: mod.ml_dsa87 };
  } catch {
    return { ok: false };
  }
}

// ------------------------------------------------------------------ the two signature halves
// Pure Ed25519 (crypto.verify(null, ...)) and ML-DSA-87 with an empty context (no options). Each verdict is
// recorded; a throw from either is reported as threw (exit 2), never as a false verdict (hybrid-verify.mjs T-S6).
export function verifyPair(preimage, edSig, mlSig, edSpki, mlPk, ml_dsa87) {
  const msg = Buffer.from(preimage, "latin1");
  let ed = false, ml = false, threw = false;
  try {
    ed = cryptoVerify(null, msg, createPublicKey({ key: edSpki, format: "der", type: "spki" }), edSig) === true;
  } catch {
    threw = true;
  }
  try {
    ml = ml_dsa87.verify(new Uint8Array(mlSig), new Uint8Array(msg), new Uint8Array(mlPk)) === true;
  } catch {
    threw = true;
  }
  return { ed, ml, threw };
}

// ------------------------------------------------------------------ CA-0's known answers (v7 2.6, 3.8, A2-11)
// The three v3 vectors reproduce: the KAT key_id recomputes; each preimage is built and equals the vector; both
// signatures verify over their own kind's preimage and fail over the other two kinds'. Prints nothing itself; the
// caller prints only `KAT-OK <count>` (SAC-L3).
export function katSelfTest(katPath, ml_dsa87) {
  let n = 0;
  try {
    const bytes = readFileSync(katPath);
    if (sha256(bytes) !== KAT_SHA256) return { ok: false };
    n++;
    const kat = JSON.parse(bytes.toString("utf8"));
    const kf = JSON.parse(kat.key_file.text);
    const edSpki = Buffer.from(kf.ed25519_spki_der, "hex"), mlPk = Buffer.from(kf.mldsa87_pk, "hex");
    if (C.keyIdOf(edSpki, mlPk) !== kat.key_id || kf.key_id !== kat.key_id) return { ok: false };
    n++;
    const texts = { history: kat.history_file_text, key: kat.statement_file_text };
    const pre = {};
    for (const kind of KINDS) {
      const v = kat.vectors[kind];
      let p;
      if (kind === "anchor") {
        p = C.PREIMAGE_PREFIX.anchor + kat.key_id + ":" + v.file_sha3_256;
      } else {
        const fb = Buffer.from(texts[kind], "utf8");
        if (sha3(fb) !== v.file_sha3_256 || sha256(fb) !== v.file_sha256 || fb.length !== v.file_octets) return { ok: false };
        p = C.preimageOf(kind, kat.key_id, fb);
      }
      if (p !== v.preimage_ascii || p.length !== v.preimage_octets || sha256(Buffer.from(p, "latin1")) !== v.preimage_sha256) return { ok: false };
      pre[kind] = p;
      n++;
    }
    for (const kind of KINDS) {
      const v = kat.vectors[kind];
      const edSig = Buffer.from(v.ed25519_sig_hex, "hex"), mlSig = Buffer.from(v.mldsa87_sig_hex, "hex");
      if (mlSig.length !== 4627 || sha256(mlSig) !== v.mldsa87_sig_sha256) return { ok: false };
      for (const other of KINDS) {
        const r = verifyPair(pre[other], edSig, mlSig, edSpki, mlPk, ml_dsa87);
        if (r.threw) return { ok: false };
        const want = other === kind;
        if (r.ed !== want || r.ml !== want) return { ok: false };
        n += 2;
      }
    }
    return { ok: true, count: n };
  } catch {
    return { ok: false };
  }
}

// ------------------------------------------------------------------ CA-2 to CA-5, the key file
const ED_HEAD = Buffer.from(C.ED25519_SPKI_HEAD_HEX, "hex");
// Returns { ok: true, kf } with kf = { obj, edSpki, mlPk, keyId, sha256, sha3_256 }, or { ok: false, id, msg }.
// pinnedKeyId null skips CA-5 (--print-key-id runs CA-1 to CA-4).
export function checkKeyFile(buf, pinnedKeyId, deny = DENY) {
  const fail = (id, msg) => ({ ok: false, id, msg });
  const o = C.parseCanonical(buf);
  if (o === null) return fail("CA-2", "the key file is not canonical ASCII JSON");
  if (!C.sameKeys(o, C.KEY_FILE_MEMBERS)) return fail("CA-2", "the key file does not have exactly the nine members in order");
  if (o.purpose !== C.KEY_FILE_PURPOSE || o.alg !== C.SIDECAR_ALG || o.status !== "active") return fail("CA-2", "purpose, alg or status is not as section 2.4 fixes it");
  if (!C.HEX64.test(o.key_id) || !C.HEX64.test(o.birth_record)) return fail("CA-2", "key_id or birth_record is not 64 lowercase hex");
  if (!C.isHex(o.ed25519_spki_der, 2 * C.ED25519_SPKI_OCTETS) || !C.isHex(o.mldsa87_pk, 5184)) return fail("CA-2", "a public key is not lowercase hex of its exact length");
  if (!C.isDate(o.valid_from) || !C.isDate(o.rotate_by)) return fail("CA-2", "valid_from or rotate_by is not YYYY-MM-DD");
  const edSpki = Buffer.from(o.ed25519_spki_der, "hex");
  const mlPk = Buffer.from(o.mldsa87_pk, "hex");
  if (!edSpki.subarray(0, ED_HEAD.length).equals(ED_HEAD)) return fail("CA-2", "the Ed25519 SPKI does not carry the Ed25519 head");
  try {
    const k = createPublicKey({ key: edSpki, format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519" || !k.export({ format: "der", type: "spki" }).equals(edSpki)) return fail("CA-2", "the Ed25519 SPKI is not canonical DER");
  } catch {
    return fail("CA-2", "the Ed25519 SPKI does not parse");
  }
  const keyId = C.keyIdOf(edSpki, mlPk);
  if (keyId !== o.key_id) return fail("CA-3", "the key file's key_id does not recompute from its two keys");
  if (deny.KEY_IDS.includes(keyId) || deny.ED25519_SPKI_SHA256.includes(sha256(edSpki)) || deny.MLDSA87_RAW_SHA256.includes(sha256(mlPk))) {
    return fail("CA-4", "the key, or one of its halves, is on the deny list");
  }
  if (pinnedKeyId !== null && keyId !== pinnedKeyId) return fail("CA-5", "the key file's key_id is not the pinned anchor-signer key_id");
  return { ok: true, kf: { obj: o, edSpki, mlPk, keyId, sha256: sha256(buf), sha3_256: sha3(buf) } };
}

// ------------------------------------------------------------------ the anchor document (SA-A1, SA-A5, SA-A6, SA-A8)
// Shared with sign-anchor --prepare (v2 3.2). Returns null when every rule holds, else the failing id.
export function anchorRulesA1(a) {
  if (!C.isPlainObject(a) || !C.isDate(a.snapshot_taken) || !C.isDate(a.next_update)) return "SA-A1";
  if (C.addDays(a.snapshot_taken, 30) !== a.next_update) return "SA-A1";
  return null;
}
export function anchorRulesA5(a) {
  if (!C.isPlainObject(a.issuers)) return "SA-A5";
  for (const entries of Object.values(a.issuers)) {
    if (!Array.isArray(entries)) return "SA-A5";
    for (const e of entries) {
      if (!C.isPlainObject(e) || !C.HEX64.test(e.key_id) || !C.isHex(e.ed25519_spki_der, 88) || !C.isHex(e.mldsa87_pk, 5184)) return "SA-A5";
      if (C.keyIdOf(Buffer.from(e.ed25519_spki_der, "hex"), Buffer.from(e.mldsa87_pk, "hex")) !== e.key_id) return "SA-A5";
    }
  }
  return null;
}
export function anchorRulesA6(a, kf) {
  for (const entries of Object.values(a.issuers)) {
    for (const e of entries) {
      if (e.key_id === kf.keyId || e.ed25519_spki_der === kf.obj.ed25519_spki_der || e.mldsa87_pk === kf.obj.mldsa87_pk) return "SA-A6";
    }
  }
  return null;
}
export function anchorRulesA8(a) {
  return Object.hasOwn(a, "profile_policy") ? "SA-A8" : null;
}

// ------------------------------------------------------------------ CA-9 for key statements (v7 5.4, A-7; v2 CA-9)
// Returns null or { id, msg, exit }. lines receives informational lines (revoke's possession note).
export function checkStatementDoc(o, ctx, lines) {
  const fail = (id, msg, exit = 1) => ({ id, msg, exit });
  if (o.statement !== "talon-anchor-key") return fail("CA-9 STATEMENT", "statement is not talon-anchor-key");
  if (o.version !== 1) return fail("CA-9 VERSION", "version is not 1");
  if (o.kind !== ctx.statementKind) return fail("CA-9 K-KIND", "the statement's kind is not the kind asked for");
  if (!C.sameKeys(o, STATEMENT_MEMBERS[ctx.statementKind])) return fail("CA-9 MEMBERS", "the statement does not have exactly its kind's members in order");
  const kf = ctx.kf;
  if (ctx.statementKind === "announce") {
    if (o.key_id !== kf.keyId) return fail("CA-9 KEY-ID", "key_id is not the key file's recomputed key_id");
    if (o.key_file_sha256 !== kf.sha256) return fail("CA-9 KEY-FILE-SHA256", "key_file_sha256 is not the key file's sha256");
    if (o.key_file_sha3_256 !== kf.sha3_256) return fail("CA-9 KEY-FILE-SHA3-256", "key_file_sha3_256 is not the key file's sha3-256");
    if (!C.isDate(o.date)) return fail("CA-9 DATE-FORMAT", "date is not YYYY-MM-DD");
    let anchor = null;
    try {
      anchor = JSON.parse(ctx.anchorBuf.toString("utf8"));
    } catch {
      anchor = null;
    }
    if (!C.isPlainObject(anchor) || o.date !== anchor.snapshot_taken) return fail("CA-9 DATE-ANCHOR", "date is not the snapshot_taken of the anchor given with --anchor");
    if (ctx.historyBuf !== null) {
      let h = null;
      try {
        h = JSON.parse(ctx.historyBuf.toString("utf8"));
      } catch {
        h = null;
      }
      const entries = C.isPlainObject(h) && Array.isArray(h.entries) ? h.entries : [];
      const first = entries.find((e) => C.isPlainObject(e) && e.signer_key_id === kf.keyId);
      if (first === undefined || first.sha256 !== sha256(ctx.anchorBuf)) return fail("CA-9 HISTORY-ANCHOR", "the anchor is not the first history entry signed by this key");
    }
    if (o.text !== ANNOUNCE_TEXT) return fail("CA-9 TEXT", "text is not the announce text exactly");
    return null;
  }
  if (ctx.statementKind === "rotate") {
    const nk = checkKeyFile(ctx.newKeyFileBuf, null, ctx.deny);
    if (!nk.ok) return fail(`CA-9 NEW-${nk.id}`, `the new key file: ${nk.msg}`);
    const side = checkSidecar(ctx.newSigBuf, "key", ctx.fileBuf, nk.kf, ctx.ml_dsa87);
    if (side !== null) return fail(`CA-9 NEW-${side.id}`, `the new key's signature: ${side.msg}`, side.exit);
    if (o.new_key_id !== nk.kf.keyId) return fail("CA-9 NEW-KEY-ID", "new_key_id is not the new key file's recomputed key_id");
    return null;
  }
  if (o.key_id !== kf.keyId) return fail("CA-9 KEY-ID", "key_id is not the key file's recomputed key_id");
  lines.push("REVOKE-NOTE a valid signature on a revocation proves possession only");
  return null;
}

// ------------------------------------------------------------------ CA-6, CA-7, CA-8 (v2 5.4, kept)
// Returns null or { id, msg, exit }. CA-6 is v2's shape test exactly; the display fields are CA-7's.
export function checkSidecar(sigBuf, kind, fileBuf, kf, ml_dsa87, lines = null) {
  const o = C.parseCanonical(sigBuf);
  if (o === null || !C.sameKeys(o, C.SIDECAR_MEMBERS)) return { id: "CA-6", msg: "the sidecar is not canonical with exactly the seven members in order", exit: 1 };
  if (o.kind !== kind) return { id: "CA-6", msg: "the sidecar's kind is not the kind asked for", exit: 1 };
  if (!C.isHex(o.ed25519, 128) || !C.isHex(o.mldsa87, 9254)) return { id: "CA-6", msg: "a signature member is not lowercase hex of its exact length", exit: 1 };
  if (lines) lines.push("CA-6 OK");
  const preimage = C.preimageOf(kind, kf.keyId, fileBuf);
  if (o.alg !== C.SIDECAR_ALG) return { id: "CA-7", msg: "alg is not Ed25519+ML-DSA-87", exit: 1 };
  if (o.key_id !== kf.keyId) return { id: "CA-7", msg: "the display key_id is not the recomputed key_id", exit: 1 };
  if (o.file_sha256 !== sha256(fileBuf)) return { id: "CA-7", msg: "the display file_sha256 is not the file's sha256", exit: 1 };
  if (o.preimage !== preimage) return { id: "CA-7", msg: "the display preimage is not the recomputed preimage", exit: 1 };
  if (lines) lines.push("CA-7 OK");
  const v = verifyPair(preimage, Buffer.from(o.ed25519, "hex"), Buffer.from(o.mldsa87, "hex"), kf.edSpki, kf.mlPk, ml_dsa87);
  if (v.threw) return { id: "CA-8", msg: "a signature library threw (exit 2)", exit: 2 };
  if (!(v.ed === true && v.ml === true)) return { id: "CA-8", msg: `ed25519=${v.ed} mldsa87=${v.ml}`, exit: 1 };
  if (lines) lines.push("CA-8 OK ed25519=true mldsa87=true");
  return null;
}

// ------------------------------------------------------------------ CA-2 to CA-10 over buffers (also --assemble's)
// a = { kind, statementKind, fileBuf, sigBuf, keyFileBuf, pinnedKeyId, deny, ml_dsa87, clockSec,
//       anchorBuf, historyBuf, previousBuf, anchorsDir, newKeyFileBuf, newSigBuf }
// Returns { exit, id, msg, lines, kf, fileSha256, fileSha3 }.
export function checkArtifact(a) {
  const lines = [];
  const stop = (id, msg, exit = 1) => ({ exit, id, msg, lines });
  const k = checkKeyFile(a.keyFileBuf, a.pinnedKeyId, a.deny ?? DENY);
  if (!k.ok) {
    for (const id of ["CA-2", "CA-3", "CA-4"]) if (id < k.id) lines.push(`${id} OK`);
    return stop(k.id, k.msg);
  }
  lines.push("CA-2 OK", "CA-3 OK", "CA-4 OK", "CA-5 OK");
  const kf = k.kf;
  const side = checkSidecar(a.sigBuf, a.kind, a.fileBuf, kf, a.ml_dsa87, lines);
  if (side !== null) return stop(side.id, side.msg, side.exit);
  const doc = C.parseCanonical(a.fileBuf);
  if (doc === null) return stop("CA-9 CANONICAL", "the document is not canonical ASCII JSON");
  if (a.kind === "anchor") {
    // T12b-3: the rules run one after another in the design's order (v2:329), so a later rule never reads what an
    // earlier one refused (a signed anchor without an issuers object fails at SA-A5, never crashes at SA-A6).
    for (const rule of [() => anchorRulesA1(doc), () => anchorRulesA5(doc), () => anchorRulesA6(doc, kf), () => anchorRulesA8(doc)]) {
      const r = rule();
      if (r !== null) return stop(`CA-9 ${r}`, "the anchor breaks this rule of section 3.2");
    }
    const att = C.isPlainObject(doc.attested_verifier) ? doc.attested_verifier : {};
    const vm = C.HEX64.test(att.verify_mjs_sha256 ?? "") ? att.verify_mjs_sha256 : "absent";
    const mf = C.HEX64.test(att.manifest_sha256 ?? "") ? att.manifest_sha256 : "absent";
    lines.push(`ATTESTED verify_mjs_sha256=${vm} manifest_sha256=${mf} (compare with your own pins)`);
  } else if (a.kind === "history") {
    const prev = a.previousBuf ? a.previousBuf.toString("latin1") : null;
    const h = C.hRules(a.fileBuf.toString("latin1"), { pinnedKeyId: kf.keyId, previousText: prev });
    if (h !== "OK") return stop(`CA-9 ${h}`, "the history breaks this rule of section 2.7");
    if (a.anchorsDir) {
      let checked = 0;
      for (const e of doc.entries) {
        const p = join(a.anchorsDir, e.file);
        let st = null;
        try {
          st = lstatSync(p);
        } catch {
          st = null;
        }
        if (st === null) continue;
        if (!st.isFile()) return stop("CA-9 ANCHORS-DIR", "a listed file is present but is not a regular file");
        const b = readFileSync(p);
        if (sha256(b) !== e.sha256 || sha3(b) !== e.sha3_256) return stop("CA-9 ANCHORS-DIR", "a listed file present under --anchors-dir does not hash as listed");
        checked++;
      }
      lines.push(`ANCHORS-DIR checked ${checked} of ${doc.entries.length}`);
    }
  } else {
    const r = checkStatementDoc(doc, { statementKind: a.statementKind, kf, anchorBuf: a.anchorBuf, historyBuf: a.historyBuf ?? null,
      newKeyFileBuf: a.newKeyFileBuf, newSigBuf: a.newSigBuf, fileBuf: a.fileBuf, ml_dsa87: a.ml_dsa87, deny: a.deny ?? DENY }, lines);
    if (r !== null) return stop(r.id, r.msg, r.exit);
  }
  lines.push("CA-9 OK");
  if (a.kind === "anchor") {
    const snap = C.dateEpoch(doc.snapshot_taken), next = C.dateEpoch(doc.next_update);
    if (a.clockSec < snap) return stop("CA-10 D-FUTURE", "the clock is before the anchor's snapshot_taken");
    if (a.clockSec > next) return stop("CA-10 D-EXPIRED", "the clock is after the anchor's next_update", 2);
    lines.push("CA-10 OK");
  }
  return { exit: 0, lines, kf, fileSha256: sha256(a.fileBuf), fileSha3: sha3(a.fileBuf) };
}

// ------------------------------------------------------------------ the CLI layer: CA-0, CA-1, PIN-DISAGREES
const FLAGS = Object.freeze({
  anchor: ["--kind", "--file", "--sig", "--key-file", "--expect-key-id", "--clock", "--noble"],
  history: ["--kind", "--file", "--sig", "--key-file", "--previous", "--anchors-dir", "--noble"],
  announce: ["--kind", "--statement-kind", "--file", "--sig", "--key-file", "--anchor", "--history", "--noble"],
  rotate: ["--kind", "--statement-kind", "--file", "--sig", "--key-file", "--new-key-file", "--new-sig", "--noble"],
  revoke: ["--kind", "--statement-kind", "--file", "--sig", "--key-file", "--noble"],
  print: ["--print-key-id", "--noble"],
});
function parsePairs(argv) {
  const m = new Map();
  if (argv.length % 2 !== 0) return null;
  for (let i = 0; i < argv.length; i += 2) {
    const f = argv[i], v = argv[i + 1];
    if (typeof f !== "string" || !f.startsWith("--") || typeof v !== "string" || v.length === 0 || m.has(f)) return null;
    m.set(f, v);
  }
  return m;
}
function isRegularFile(p) {
  try {
    return lstatSync(p).isFile();
  } catch {
    return false;
  }
}
function isDir(p) {
  try {
    return lstatSync(p).isDirectory();
  } catch {
    return false;
  }
}

// The core. p = { argv, pinnedKeyId, clock (ms, default the system clock), katPath, nobleDir, deny, mldsaOverride, print }.
// Returns the exit code; prints its lines at the end through p.print.
// T12b-4 (T13cb A-3 as a rule; R-93): any internal error ends in one fixed line, CA-INTERNAL, exit 2; its text is
// discarded; never a trace and never exit 1.
export async function checkAnchorCore(p) {
  try {
    return await checkAnchorRun(p);
  } catch {
    (p.print ?? ((l) => process.stdout.write(l + "\n")))("CHECK-ANCHOR FAIL CA-INTERNAL: the checker stopped on an unexpected condition; its text was discarded");
    return 2;
  }
}
async function checkAnchorRun(p) {
  const out = [];
  const emit = p.print ?? ((l) => process.stdout.write(l + "\n"));
  const done = (exit, id, msg) => {
    if (id) out.push(`CHECK-ANCHOR FAIL ${id}: ${msg}`);
    for (const l of out) emit(l);
    return exit;
  };
  const pairs = parsePairs(p.argv);
  // CA-0, start-up. --noble is read here, before any other argument is judged (CA-1).
  const nobleDir = (pairs && pairs.get("--noble")) ?? p.nobleDir ?? DEFAULT_NOBLE_DIR;
  const pin = p.pinnedKeyId;
  const deny = p.deny ?? DENY;
  if (typeof pin !== "string" || !C.HEX64.test(pin) || deny.KEY_IDS.includes(pin)) return done(2, "CA-0", "the pinned anchor-signer key_id is not set, not 64 lowercase hex, or denied");
  const noble = await loadNoble(nobleDir);
  if (!noble.ok) return done(2, "CA-0", "the vendored @noble trees do not match their pins or cannot be loaded");
  if (process.versions.node.split(".")[0] !== "20") return done(2, "CA-0", "node major version is not 20");
  const ml_dsa87 = p.mldsaOverride ?? noble.ml_dsa87;
  const kat = katSelfTest(p.katPath ?? DEFAULT_KAT_PATH, noble.ml_dsa87);
  if (!kat.ok) return done(2, "CA-0", "the known-answer vectors do not reproduce");
  out.push(`KAT-OK ${kat.count}`);
  // CA-1, invocation.
  if (pairs === null) return done(2, "CA-1", "arguments are not --flag value pairs, or a flag is repeated");
  let form;
  if (pairs.has("--print-key-id")) form = "print";
  else if (pairs.get("--kind") === "key") form = pairs.get("--statement-kind");
  else form = pairs.get("--kind");
  if (!Object.hasOwn(FLAGS, form)) return done(2, "CA-1", "--kind (and --statement-kind for key) is missing or not valid");
  for (const f of pairs.keys()) if (!FLAGS[form].includes(f)) return done(2, "CA-1", "an argument is not valid for this kind");
  const need = form === "print" ? ["--print-key-id"] : ["--file", "--sig", "--key-file"];
  if (form === "announce") need.push("--anchor");
  if (form === "rotate") need.push("--new-key-file", "--new-sig");
  for (const f of need) if (!pairs.has(f)) return done(2, "CA-1", "a required argument is missing");
  for (const f of ["--print-key-id", "--file", "--sig", "--key-file", "--anchor", "--history", "--previous", "--new-key-file", "--new-sig"]) {
    if (pairs.has(f) && !isRegularFile(pairs.get(f))) return done(2, "CA-1", "a named file is not a regular file (a symbolic link is refused) or cannot be read");
  }
  if (pairs.has("--anchors-dir") && !isDir(pairs.get("--anchors-dir"))) return done(2, "CA-1", "--anchors-dir is not a directory");
  let clockSec = Math.floor((p.clock ? p.clock() : Date.now()) / 1000);
  if (pairs.has("--clock")) {
    const c = C.parseInstant(pairs.get("--clock"));
    if (c === null) return done(2, "CA-1", "--clock is not an ISO 8601 instant with Z or an offset");
    clockSec = c;
  }
  if (pairs.has("--expect-key-id") && !C.HEX64.test(pairs.get("--expect-key-id"))) return done(2, "CA-1", "--expect-key-id is not 64 lowercase hex");
  let bufs;
  try {
    bufs = {};
    for (const f of ["--print-key-id", "--file", "--sig", "--key-file", "--anchor", "--history", "--previous", "--new-key-file", "--new-sig"]) {
      if (pairs.has(f)) bufs[f] = readFileSync(pairs.get(f));
    }
  } catch {
    return done(2, "CA-1", "a named file cannot be read");
  }
  out.push("CA-1 OK");
  if (pairs.has("--expect-key-id") && pairs.get("--expect-key-id") !== pin) {
    return done(2, "PIN-DISAGREES", "the key_id you pinned out of band is not this checker's pinned key_id; the two trust different keys");
  }
  if (form === "print") {
    const k = checkKeyFile(bufs["--print-key-id"], null, deny);
    if (!k.ok) return done(k.id === "CA-2" || k.id === "CA-3" || k.id === "CA-4" ? 1 : 2, k.id, k.msg);
    out.push("CA-2 OK", "CA-3 OK", "CA-4 OK", `KEY-ID ${k.kf.keyId}`, `EQUALS-PINNED ${k.kf.keyId === pin ? "yes" : "no"}`);
    return done(k.kf.keyId === pin ? 0 : 1);
  }
  const kind = pairs.get("--kind");
  const r = checkArtifact({
    kind, statementKind: kind === "key" ? form : null, fileBuf: bufs["--file"], sigBuf: bufs["--sig"], keyFileBuf: bufs["--key-file"],
    pinnedKeyId: pin, deny, ml_dsa87, clockSec, anchorBuf: bufs["--anchor"] ?? null, historyBuf: bufs["--history"] ?? null,
    previousBuf: bufs["--previous"] ?? null, anchorsDir: pairs.get("--anchors-dir") ?? null,
    newKeyFileBuf: bufs["--new-key-file"] ?? null, newSigBuf: bufs["--new-sig"] ?? null,
  });
  out.push(...r.lines);
  if (r.exit !== 0) return done(r.exit, r.id, r.msg);
  out.push(`CHECK-ANCHOR PASS kind=${kind} key_id=${r.kf.keyId} file_sha256=${r.fileSha256} file_sha3_256=${r.fileSha3}`);
  return done(0);
}

// ------------------------------------------------------------------ the CLI entry
function isMainModule() {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}
if (isMainModule()) {
  process.exitCode = await checkAnchorCore({ argv: process.argv.slice(2), pinnedKeyId: ANCHOR_SIGNER_KEY_ID });
}
