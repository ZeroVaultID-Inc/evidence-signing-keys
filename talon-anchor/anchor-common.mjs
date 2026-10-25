// anchor-common.mjs: the single implementation, for the TALON anchor tools, of the key_id (design v8c section 2.1),
// the three preimages (2.2), the sidecar shape (2.3), the key file shape (2.4), the canonical-JSON rule (2.5), the
// history rules (2.7, 2.8), the date rules (8.1, 8.2), the one-way key fingerprint (6.1) and the output gate (3.4).
// Imported by ct-check.mjs and anchor-history.mjs (the early set), and later by
// sign-anchor and check-anchor. Design: ANCHOR-SIGN-DESIGN-v8c.md (with its
// ERRATA-1).
// Offline; node: builtins only; no
// environment variable is read; nothing is written by this module.
import { createHash } from "node:crypto";

export const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
export const sha3Hex = (b) => createHash("sha3-256").update(b).digest("hex");
export const HEX64 = /^[0-9a-f]{64}$/;
export function isHex(s, n) { return typeof s === "string" && s.length === n && /^[0-9a-f]*$/.test(s); }

// ------------------------------------------------------------------ 2.1 the key_id
export const KEY_ALG = "ed25519+ml-dsa-87";
export function keyIdOf(edSpkiDer, mlPk) {
  const rec = { alg: KEY_ALG, ed25519: Buffer.from(edSpkiDer).toString("hex"), mldsa87: Buffer.from(mlPk).toString("hex") };
  return sha3Hex(Buffer.from(JSON.stringify(rec, Object.keys(rec).sort()), "utf8"));
}
export const ED25519_SPKI_HEAD_HEX = "302a300506032b6570032100";
export const MLDSA87_SPKI_HEAD_HEX = "30820a32300b060960864801650304031303820a2100"; // seal-keys.mjs:25
export const ED25519_SPKI_OCTETS = 44;
export const MLDSA87_SPKI_OCTETS = 2614;
export const MLDSA87_HEAD_OCTETS = 22;

// ------------------------------------------------------------------ 2.5 the canonical-JSON rule
export function canonicalText(obj) { return JSON.stringify(obj, null, 2) + "\n"; }
export function isAsciiBytes(buf) { for (const c of buf) if (c > 0x7f) return false; return true; }
export function isPrintableAscii(s) { return typeof s === "string" && /^[\x20-\x7e]*$/.test(s); }
// Returns the parsed object when bytes == utf8(JSON.stringify(JSON.parse(bytes), null, 2) + "\n") and the bytes are ASCII; else null.
export function parseCanonical(buf) {
  const b = Buffer.from(buf);
  if (!isAsciiBytes(b)) return null;
  const text = b.toString("latin1");
  let obj;
  try { obj = JSON.parse(text); } catch { return null; }
  if (canonicalText(obj) !== text) return null;
  return obj;
}
export function isPlainObject(o) { return typeof o === "object" && o !== null && !Array.isArray(o); }
export function sameKeys(o, names) { return isPlainObject(o) && JSON.stringify(Object.keys(o)) === JSON.stringify(names); }

// ------------------------------------------------------------------ 2.2 the three preimages
export const PREIMAGE_PREFIX = Object.freeze({
  anchor: "talon-anchor:v1:ed25519+ml-dsa-87:",
  history: "talon-anchor-history:v1:ed25519+ml-dsa-87:",
  key: "talon-anchor-key:v1:ed25519+ml-dsa-87:",
});
export const PREIMAGE_OCTETS = Object.freeze({ anchor: 163, history: 171, key: 167 });
export function preimageOf(kind, keyId, fileBytes) {
  if (!Object.hasOwn(PREIMAGE_PREFIX, kind) || !HEX64.test(keyId)) throw new Error("PREIMAGE-INPUT");
  const p = PREIMAGE_PREFIX[kind] + keyId + ":" + sha3Hex(Buffer.from(fileBytes));
  if (p.length !== PREIMAGE_OCTETS[kind] || !/^[a-z0-9:+-]+$/.test(p) || p.length > 4096) throw new Error("PREIMAGE-SHAPE");
  return p;
}

// ------------------------------------------------------------------ 2.3 the sidecar <file>.sig.json
export const SIDECAR_MEMBERS = ["kind", "alg", "key_id", "file_sha256", "preimage", "ed25519", "mldsa87"];
export const SIDECAR_ALG = "Ed25519+ML-DSA-87";
// Shape only (2.3): exactly seven members in order, canonical, ASCII; the display fields well formed. It verifies no
// signature: that is sign-anchor --assemble's and check-anchor's work.
export function sidecarShape(buf) {
  const o = parseCanonical(buf);
  if (o === null || !sameKeys(o, SIDECAR_MEMBERS)) return null;
  if (!Object.hasOwn(PREIMAGE_PREFIX, o.kind) || o.alg !== SIDECAR_ALG) return null;
  if (!HEX64.test(o.key_id) || !HEX64.test(o.file_sha256)) return null;
  if (typeof o.preimage !== "string" || o.preimage.length !== PREIMAGE_OCTETS[o.kind]) return null;
  if (!o.preimage.startsWith(PREIMAGE_PREFIX[o.kind] + o.key_id + ":") || !HEX64.test(o.preimage.slice(-64))) return null;
  if (!isHex(o.ed25519, 128) || !isHex(o.mldsa87, 9254)) return null;
  return o;
}

// ------------------------------------------------------------------ 2.4 the key file anchor-signer.json
export const KEY_FILE_MEMBERS = ["purpose", "alg", "key_id", "ed25519_spki_der", "mldsa87_pk", "valid_from", "rotate_by", "status", "birth_record"];
export const KEY_FILE_PURPOSE = "TALON anchor signing only";
export const KEY_FILE_ROTATE_BY = "2027-10-01";
export function keyFileText(keyId, edSpkiDer, mlPk, validFrom, birthRecordSha256) {
  return canonicalText({
    purpose: KEY_FILE_PURPOSE, alg: SIDECAR_ALG, key_id: keyId, ed25519_spki_der: Buffer.from(edSpkiDer).toString("hex"),
    mldsa87_pk: Buffer.from(mlPk).toString("hex"), valid_from: validFrom, rotate_by: KEY_FILE_ROTATE_BY, status: "active",
    birth_record: birthRecordSha256,
  });
}

// ------------------------------------------------------------------ 3.4 the output gate (tool M's patterns, plus the bare key id and the device path)
export const GATE_PATTERNS = Object.freeze([
  /arn:aws:\S*/,
  /(?<![A-Za-z0-9])[0-9]{12}(?![A-Za-z0-9])/,
  /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/,
  /[^\n]*Enter MFA code[^\n]*/,
  /(?<![A-Za-z0-9-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9-])/,
  /:(?:mfa|u2f|sms-mfa)\//,
]);
export function gateFinds(text) { return GATE_PATTERNS.some((p) => p.test(text)); }
// Every line and every file text a tool would release goes through gate() first; one match blocks all of it.
export function gate(texts) {
  for (const t of texts) if (gateFinds(t)) return { verdict: "LEAK-BLOCKED", lines: [] };
  return { verdict: "OUT", lines: texts };
}

// ------------------------------------------------------------------ 6.1 the one-way key fingerprint
export function keyIdFingerprint(arn) { return sha256Hex(Buffer.from(arn, "utf8")); }

// ------------------------------------------------------------------ 8.1 and 8.2 the date rules
const INSTANT_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|([+-])([0-9]{2}):([0-9]{2}))$/;
const DATE_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;
function daysIn(y, m) { return [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]; }
function validYmd(y, m, d) { return y >= 1 && m >= 1 && m <= 12 && d >= 1 && d <= daysIn(y, m); }
// SA-D0's form: YYYY-MM-DDThh:mm:ss with Z or an explicit +hh:mm / -hh:mm offset. Returns UTC epoch seconds, or null.
export function parseInstant(s) {
  if (typeof s !== "string") return null;
  const m = INSTANT_RE.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (!validYmd(y, mo, d) || h > 23 || mi > 59 || se > 59) return null;
  let off = 0;
  if (m[7] !== "Z") {
    const oh = Number(m[9]), om = Number(m[10]);
    if (oh > 23 || om > 59) return null;
    off = (m[8] === "+" ? 1 : -1) * (oh * 3600 + om * 60);
  }
  return Date.UTC(y, mo - 1, d, h, mi, se) / 1000 - off;
}
export function isDate(s) {
  if (typeof s !== "string") return false;
  const m = DATE_RE.exec(s);
  return !!m && validYmd(Number(m[1]), Number(m[2]), Number(m[3]));
}
function pad(n, w = 2) { return String(n).padStart(w, "0"); }
export function utcDateOf(sec) { const t = new Date(sec * 1000); return `${pad(t.getUTCFullYear(), 4)}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`; }
export function instantZ(sec) { const t = new Date(sec * 1000); return `${utcDateOf(sec)}T${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}:${pad(t.getUTCSeconds())}Z`; }
// (v8) The instant rendered in New York's offset at that instant
// (8.1): the US rule since 2007, daylight time (-04:00, EDT) from 07:00:00Z on the second Sunday of March to
// 06:00:00Z on the first Sunday of November, standard time (-05:00, EST) otherwise; the year is the instant's UTC year.
function nthSundayUTC(year, month, n) {
  const dow = new Date(Date.UTC(year, month - 1, 1)).getUTCDay();
  return Date.UTC(year, month - 1, 1 + ((7 - dow) % 7) + 7 * (n - 1)) / 1000;
}
export function nyOffsetHours(sec) {
  const y = new Date(sec * 1000).getUTCFullYear();
  return sec >= nthSundayUTC(y, 3, 2) + 7 * 3600 && sec < nthSundayUTC(y, 11, 1) + 6 * 3600 ? -4 : -5;
}
export function instantNY(sec) {
  const off = nyOffsetHours(sec);
  return instantZ(sec + off * 3600).slice(0, 19) + (off === -4 ? "-04:00 EDT" : "-05:00 EST");
}
export function dateEpoch(dateStr) { const m = DATE_RE.exec(dateStr); return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / 1000; }
export function addDays(dateStr, n) { return utcDateOf(dateEpoch(dateStr) + n * 86400); }
const H48 = 48 * 3600;
// 8.1: D is the UTC date of T19's recorded end; checks SA-D0, SA-D1, SA-D2, then D, then SA-A3 (3.10).
export function snapshotDate(t19End, buildSec) {
  const t = parseInstant(t19End);
  if (t === null) return { fail: "SA-D0" };
  if (t > buildSec) return { fail: "SA-D1" };
  if (buildSec - t > H48) return { fail: "SA-D2" };
  const D = utcDateOf(t);
  if (buildSec - dateEpoch(D) > H48) return { fail: "SA-A3" };
  return { snapshot_taken: D, next_update: addDays(D, 30) };
}
// 8.2: the UTC date of the build if before 18:00:00Z, otherwise the next UTC date.
export function firstPublished(buildSec) {
  const D = utcDateOf(buildSec);
  return buildSec - dateEpoch(D) < 18 * 3600 ? D : addDays(D, 1);
}
export const DATE_RULE_NAME = "talon-anchor-snapshot-date";
export const DATE_JSON_MEMBERS = ["rule", "version", "t19_end", "computed_at", "snapshot_taken", "next_update"];

// ------------------------------------------------------------------ 2.7 and 2.8 HISTORY.json
export const HISTORY_WRAP = ["history", "version", "entries"];
export const ENTRY_MEMBERS = ["seq", "file", "snapshot_taken", "next_update", "sha256", "sha3_256", "signer_key_id", "sig_sha256", "first_published", "status", "note", "prev_entry_sha256"];
export const ENTRY0_NOTE = "unsigned";
export const BASE_SIGNED = "signed";
export const BASE_D8 = "unsigned; signer not cleared at GO (decision 8)";
export const BASE_D27 = "unsigned; signature withheld (decision 27)";
export const BASE_RULED = "unsigned; a signing-session check failed";
export const LATER_BASES = Object.freeze([BASE_SIGNED, BASE_D8, BASE_D27, BASE_RULED]);
const PRIOR_START = "withheld (decision 27):";
const PRIOR_RE = /^withheld \(decision 27\): anchor ([0-9a-f]{64}), key ([0-9a-f]{64}), history ([0-9a-f]{64}); /;
export function priorText(anchorSidecarSha256, keySidecarSha256, historySidecarSha256) {
  return `withheld (decision 27): anchor ${anchorSidecarSha256}, key ${keySidecarSha256}, history ${historySidecarSha256}; `;
}
export function noteBase(note) {
  if (typeof note !== "string") return null;
  const m = PRIOR_RE.exec(note);
  return m ? note.slice(m[0].length) : note;
}
export function entryWithoutStatusText(e) {
  const o = {};
  for (const k of Object.keys(e)) if (k !== "status") o[k] = e[k];
  return JSON.stringify(o, Object.keys(o).sort());
}
// prev_entry_sha256 of entry i is sha256 of entry i-1 with status removed, keys sorted, compact.
export function chainValue(e) { return sha256Hex(Buffer.from(entryWithoutStatusText(e), "utf8")); }
export const ENTRY0_FIXED = Object.freeze({
  file: "anchors/2026-10-01/anchor-snapshot.json", snapshot_taken: "2026-10-01", next_update: "2026-10-31",
  sha256: "b8a7f3201546443920c5fd3720a94313f6b6aecf68ec87b808ae1916c2379248",
  sha3_256: "303308693e7559e622ae04f5a637c9c65f213a7891559702a542f400892121a3",
});
export function makeEntry(seq, file, snapshotTaken, nextUpdate, sha256, sha3, signer, sig, fp, status, note, prev) {
  return { seq, file, snapshot_taken: snapshotTaken, next_update: nextUpdate, sha256, sha3_256: sha3, signer_key_id: signer, sig_sha256: sig,
    first_published: fp, status, note, prev_entry_sha256: prev };
}
export function entry0(fp) {
  const f = ENTRY0_FIXED;
  return makeEntry(0, f.file, f.snapshot_taken, f.next_update, f.sha256, f.sha3_256, null, null, fp, "superseded", ENTRY0_NOTE, null);
}
export function historyText(entries) { return canonicalText({ history: "talon-anchor-history", version: 1, entries }); }
const STATUS_T = new Set(["current>current", "superseded>superseded", "revoked>revoked", "current>superseded", "current>revoked", "superseded>revoked"]);
function parseJson(text) { try { return { ok: true, v: JSON.parse(text) }; } catch { return { ok: false }; } }
// The H-rules of 2.7, in their order. Returns "OK" or the first failing id. pinnedKeyId: the pin when the caller has
// one (check-anchor, sign-anchor); without one, a signer_key_id must be 64 lowercase hex. previousText: H-APPEND, H-STATUS-T.
export function hRules(text, opts = {}) {
  const pinned = opts.pinnedKeyId ?? null;
  const p = parseJson(text);
  if (!p.ok) return "H-WRAP";
  const o = p.v;
  if (!sameKeys(o, HISTORY_WRAP) || o.history !== "talon-anchor-history" || o.version !== 1 || !Array.isArray(o.entries) || o.entries.length === 0) return "H-WRAP";
  const E = o.entries;
  for (const e of E) if (!sameKeys(e, ENTRY_MEMBERS)) return "H-MEMBERS";
  for (let i = 0; i < E.length; i++) if (E[i].seq !== i) return "H-SEQ";
  if (E[0].prev_entry_sha256 !== null) return "H-PREV";
  for (let i = 1; i < E.length; i++) if (E[i].prev_entry_sha256 !== chainValue(E[i - 1])) return "H-PREV";
  for (const e of E) if (typeof e.snapshot_taken !== "string" || e.file !== `anchors/${e.snapshot_taken}/anchor-snapshot.json`) return "H-FILE";
  for (let i = 0; i < E.length; i++) {
    const e = E[i];
    if (!isDate(e.snapshot_taken) || !isDate(e.next_update) || !isDate(e.first_published)) return "H-DATES";
    if (addDays(e.snapshot_taken, 30) !== e.next_update || e.first_published < e.snapshot_taken) return "H-DATES";
    if (i > 0 && (e.snapshot_taken <= E[i - 1].snapshot_taken || e.first_published < E[i - 1].first_published)) return "H-DATES";
  }
  for (const e of E) {
    if ((e.signer_key_id === null) !== (e.sig_sha256 === null)) return "H-SIGNER";
    if (e.signer_key_id !== null && (pinned !== null ? e.signer_key_id !== pinned : !HEX64.test(e.signer_key_id))) return "H-SIGNER";
    if (e.sig_sha256 !== null && !HEX64.test(e.sig_sha256)) return "H-SIGNER";
    if ((noteBase(e.note) === BASE_SIGNED) !== (e.signer_key_id !== null)) return "H-SIGNER";
  }
  for (const e of E) if (!HEX64.test(e.sha256) || !HEX64.test(e.sha3_256)) return "H-HEX";
  for (let i = 0; i < E.length; i++) {
    const n = E[i].note;
    if (!isPrintableAscii(n) || n.length > 300) return "H-NOTE";
    if (i === 0) { if (n !== ENTRY0_NOTE) return "H-NOTE"; continue; }
    const needPrior = noteBase(E[i - 1].note) === BASE_D27;
    if (n.startsWith(PRIOR_START)) {
      const m = PRIOR_RE.exec(n);
      if (!m || !needPrior) return "H-NOTE-27";
      if (!LATER_BASES.includes(n.slice(m[0].length))) return "H-NOTE";
    } else {
      if (needPrior) return "H-NOTE-27";
      if (!LATER_BASES.includes(n)) return "H-NOTE";
    }
  }
  if (E[E.length - 1].status !== "current") return "H-STATUS";
  for (let i = 0; i < E.length - 1; i++) if (E[i].status !== "superseded" && E[i].status !== "revoked") return "H-STATUS";
  if (opts.previousText !== undefined && opts.previousText !== null) {
    const q = parseJson(opts.previousText);
    if (!q.ok || !isPlainObject(q.v) || !Array.isArray(q.v.entries)) return "H-APPEND";
    const O = q.v.entries;
    if (O.length > E.length) return "H-APPEND";
    for (let i = 0; i < O.length; i++) {
      if (!isPlainObject(O[i]) || entryWithoutStatusText(O[i]) !== entryWithoutStatusText(E[i])) return "H-APPEND";
    }
    for (let i = 0; i < O.length; i++) if (!STATUS_T.has(`${O[i].status}>${E[i].status}`)) return "H-STATUS-T";
  }
  return "OK";
}
