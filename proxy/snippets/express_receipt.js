"use strict";

// Receipt check for Express. Node crypto only.
// The memory store is one process. Several instances need a shared store.

const crypto = require("crypto");
const PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/;

function b64urlDecode(text) {
  return Buffer.from(text, "base64url");
}

function kidFor(secret) {
  return crypto.createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 16);
}

function normalizePath(path) {
  if (!path || path.length > 200 || !PATH.test(path) || path.includes("..") || path.includes("//")) return null;
  return path;
}

function verifyReceipt(token, options) {
  const typ = options.typ || "satsgate-receipt+jwt";
  const leeway = options.leeway == null ? 30 : options.leeway;
  const now = options.now == null ? Math.floor(Date.now() / 1000) : options.now;
  const issuers = new Set((options.issuers || ["https://gate.satsgate.org"]).map((item) => item.replace(/\/$/, "")));
  if (!token || !String(token).trim()) return { ok: false, code: "receipt_missing" };
  const parts = String(token).trim().split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) return { ok: false, code: "receipt_invalid" };
  let header;
  let claims;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString("utf8"));
    claims = JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  } catch (_err) {
    return { ok: false, code: "receipt_invalid" };
  }
  if (!header || header.alg !== "HS256" || header.typ !== typ) return { ok: false, code: "receipt_invalid" };
  const matched = [options.secret, ...(options.previousSecrets || [])].filter((item) => item && kidFor(item) === header.kid);
  if (!matched.length) return { ok: false, code: "receipt_invalid" };
  const signing = Buffer.from(parts[0] + "." + parts[1], "ascii");
  let presented;
  try {
    presented = b64urlDecode(parts[2]);
  } catch (_err) {
    return { ok: false, code: "receipt_invalid" };
  }
  let signed = false;
  for (const item of matched) {
    const expected = crypto.createHmac("sha256", item).update(signing).digest();
    if (presented.length === expected.length && crypto.timingSafeEqual(presented, expected)) signed = true;
  }
  if (!signed) return { ok: false, code: "receipt_invalid" };
  if (claims.aud !== options.site) return { ok: false, code: "receipt_wrong_site" };
  const expectedPath = normalizePath(options.path);
  const tokenPath = normalizePath(String(claims.sub || ""));
  if (!expectedPath || !tokenPath || tokenPath !== expectedPath) return { ok: false, code: "receipt_wrong_path" };
  if (typeof claims.iss !== "string" || !issuers.has(claims.iss.replace(/\/$/, ""))) return { ok: false, code: "receipt_invalid" };
  const exp = Number(claims.exp);
  const iat = Number(claims.iat);
  const uses = Number(claims.uses);
  if (!Number.isInteger(exp) || !Number.isInteger(iat) || !Number.isInteger(uses) || uses < 1) {
    return { ok: false, code: "receipt_invalid" };
  }
  if (now > exp + leeway) return { ok: false, code: "receipt_expired" };
  if (iat > now + leeway) return { ok: false, code: "receipt_invalid" };
  if (typeof claims.jti !== "string" || !claims.jti) return { ok: false, code: "receipt_invalid" };
  return { ok: true, code: "ok", receipt: { jti: claims.jti, uses, exp, path: tokenPath, claims } };
}

function memoryStore() {
  const rows = new Map();
  return {
    reserve(jti, uses, exp) {
      let row = rows.get(jti);
      if (!row) {
        row = { uses, committed: 0, reserved: new Set(), exp };
        rows.set(jti, row);
      }
      if (row.committed + row.reserved.size >= row.uses) {
        const error = new Error("receipt_used_up");
        error.code = "receipt_used_up";
        throw error;
      }
      const token = crypto.randomBytes(8).toString("hex");
      row.reserved.add(token);
      return { token, jti };
    },
    commit(reservation) {
      const row = rows.get(reservation.jti);
      if (!row || !row.reserved.delete(reservation.token)) return;
      row.committed += 1;
    },
    release(reservation) {
      const row = rows.get(reservation.jti);
      if (row) row.reserved.delete(reservation.token);
    },
  };
}

module.exports = { verifyReceipt, memoryStore };
