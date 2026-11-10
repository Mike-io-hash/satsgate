"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function verifyWebhook(secret, timestamp, rawBody, signature, now) {
  const skew = Math.abs(Number(now) - Number(timestamp));
  if (!Number.isFinite(skew) || skew > 300) return false;
  const expected =
    "v1=" +
    crypto.createHmac("sha256", secret).update(`${timestamp}.`).update(rawBody).digest("hex");
  const left = Buffer.from(expected);
  const right = Buffer.from(String(signature));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

const vector = JSON.parse(
  fs.readFileSync(path.join(__dirname, "fixtures", "webhook_signature_vector.json"), "utf8")
);
const body = Buffer.from(vector.body, "utf8");
if (!verifyWebhook(vector.secret, vector.timestamp, body, vector.signature, vector.now)) {
  console.error("webhook signature vector did not verify");
  process.exit(1);
}
if (verifyWebhook(vector.secret, vector.timestamp, body, vector.signature, vector.timestamp + 301)) {
  console.error("webhook signature accepted a stale timestamp");
  process.exit(1);
}
const quickstart = fs.readFileSync(path.join(__dirname, "..", "CUSTOMER_QUICKSTART.md"), "utf8");
if (!quickstart.includes(vector.signature) || !quickstart.includes("timingSafeEqual")) {
  console.error("quickstart is missing the signature vector or timingSafeEqual");
  process.exit(1);
}
console.log("webhook signature vector ok");
