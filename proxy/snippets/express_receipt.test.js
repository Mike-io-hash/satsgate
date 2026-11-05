"use strict";

const fs = require("fs");
const path = require("path");
const { verifyReceipt } = require("./express_receipt");

const file = path.join(__dirname, "..", "..", "tests", "fixtures", "receipt_vectors.json");
const vectors = JSON.parse(fs.readFileSync(file, "utf8"));
let failed = 0;
for (const vector of vectors.cases) {
  const result = verifyReceipt(vector.token, {
    secret: vector.verify_secret || vectors.secret,
    previousSecrets: vector.previous ? [vectors.previous_secret] : [],
    site: vector.site,
    path: vector.path,
    now: vectors.now,
    leeway: vectors.leeway,
  });
  const code = result.ok ? "ok" : result.code;
  if (code !== vector.expect) {
    console.error(vector.name, "got", code, "expected", vector.expect);
    failed += 1;
  }
}
if (failed) process.exit(1);
console.log("express receipt vectors ok");
