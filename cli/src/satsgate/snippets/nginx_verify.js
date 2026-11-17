"use strict";

// njs origin check. The message matches proxy/snippets/express_verify.js.
//
// js_import satsgate from /etc/satsgate/nginx_verify.js;
// js_set $satsgate_ok satsgate.nginxOk;
// then `if ($satsgate_ok = 0) { return 401; }` is not safe in nginx.
// Prefer auth_request, or deny in the js content handler below.
//
// The secret is the nginx variable $satsgate_origin_secret (set it from
// an env file, not from a client header).

function originMessage(timestamp, method, target, paymentHash) {
  return (
    String(timestamp) +
    "|" +
    String(method).toUpperCase() +
    "|" +
    target +
    "|" +
    String(paymentHash).toLowerCase()
  );
}

function parseSignature(header) {
  let timestamp = null;
  let digest = null;
  const parts = String(header || "").split(",");
  for (let i = 0; i < parts.length; i++) {
    const item = parts[i].trim();
    if (item.startsWith("t=")) {
      const raw = item.slice(2).trim();
      if (/^[0-9]+$/.test(raw)) timestamp = Number(raw);
    } else if (item.startsWith("v1=")) {
      digest = item.slice(3).trim().toLowerCase();
    }
  }
  if (timestamp === null || !/^[0-9a-f]{64}$/.test(digest || "")) return null;
  return { t: timestamp, v1: digest };
}

function verifyOriginSignature(opts) {
  const crypto = require("crypto");
  const parsed = parseSignature(opts.header);
  if (!parsed || !opts.secret) return false;
  const now = opts.now == null ? Math.floor(Date.now() / 1000) : opts.now;
  const maxSkew = opts.maxSkewSeconds == null ? 300 : opts.maxSkewSeconds;
  if (Math.abs(now - parsed.t) > maxSkew) return false;
  const expected = crypto
    .createHmac("sha256", opts.secret)
    .update(originMessage(parsed.t, opts.method, opts.target, opts.paymentHash), "utf8")
    .digest("hex");
  const left = Buffer.from(expected, "utf8");
  const right = Buffer.from(parsed.v1, "utf8");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function nginxVerify(r) {
  const secret = r.variables.satsgate_origin_secret || "";
  const header = r.headersIn["X-Satsgate-Signature"] || "";
  const paymentHash = r.headersIn["X-Satsgate-Payment-Hash"] || "";
  const ok = verifyOriginSignature({
    secret,
    header,
    method: r.method,
    target: r.variables.request_uri,
    paymentHash,
    now: Math.floor(Date.now() / 1000),
    maxSkewSeconds: 300,
  });
  if (!ok) {
    r.return(401, "invalid origin signature");
    return;
  }
  r.internalRedirect("@origin");
}

module.exports = { originMessage, verifyOriginSignature, nginxVerify };
