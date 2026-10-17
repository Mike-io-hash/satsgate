"use strict";

// Express middleware for X-Satsgate-Signature.
// SATSGATE_ORIGIN_SECRET must match the proxy.
// Message: {unix}|{METHOD}|{target}|{payment_hash}
// target is req.originalUrl (raw path plus raw query, percent-encoding kept).

const crypto = require("crypto");

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
  for (const part of String(header || "").split(",")) {
    const item = part.trim();
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

function satsgateOrigin(options) {
  const opts = options || {};
  const secret = opts.secret || process.env.SATSGATE_ORIGIN_SECRET || "";
  const maxSkewSeconds = opts.maxSkewSeconds == null ? 300 : opts.maxSkewSeconds;
  return function satsgateOriginMiddleware(req, res, next) {
    const header = req.get("x-satsgate-signature") || "";
    const paymentHash = req.get("x-satsgate-payment-hash") || "";
    const ok = verifyOriginSignature({
      secret,
      header,
      method: req.method,
      target: req.originalUrl,
      paymentHash,
      maxSkewSeconds,
    });
    if (!ok) {
      res.status(401).json({ ok: false, error: "invalid origin signature" });
      return;
    }
    next();
  };
}

module.exports = { originMessage, verifyOriginSignature, satsgateOrigin };
