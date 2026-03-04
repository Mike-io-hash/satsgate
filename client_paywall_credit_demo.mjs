// Full demo: challenge -> pay invoice via NWC -> verify (consumes 1 credit)
//
// Requirements:
// - server running (uvicorn)
// - satsgate API key (you get it after /v1/topup/...)
// - a payer wallet with NWC (CoinOS, etc.)
//
// Env vars:
//   SATSGATE_CLIENT_API_KEY='sg_...'
//   SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...'
//   SATSGATE_PAYEE_LNADDR='user@domain' (optional; if omitted, uses the client's registered payee)
//   SATSGATE_BASE_URL='http://127.0.0.1:8000' (optional)
//
// Usage:
//   node client_paywall_credit_demo.mjs <resource> <amount_sats>
//
import { LN } from "@getalby/sdk";

const BASE_URL = (process.env.SATSGATE_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const API_KEY = process.env.SATSGATE_CLIENT_API_KEY;
const PAYER_NWC = process.env.SATSGATE_TEST_PAYER_NWC;
const PAYEE = process.env.SATSGATE_PAYEE_LNADDR;

const RESOURCE = process.argv[2] || "demo-resource";
const AMOUNT_SATS = parseInt(process.argv[3] || "10", 10);

if (!API_KEY) {
  console.error("Missing SATSGATE_CLIENT_API_KEY (sg_...)");
  process.exit(2);
}
if (!PAYER_NWC) {
  console.error("Missing SATSGATE_TEST_PAYER_NWC (nostr+walletconnect://...)");
  process.exit(2);
}

async function getBalance() {
  const r = await fetch(`${BASE_URL}/v1/balance`, { headers: { "X-Api-Key": API_KEY } });
  return { status: r.status, body: await r.json() };
}

async function main() {
  console.log("Balance BEFORE:", await getBalance());

  // 1) Challenge
  const challengeBody = {
    amount_sats: AMOUNT_SATS,
    resource: RESOURCE,
    memo: `satsgate demo ${RESOURCE}`,
    ttl_seconds: 600,
  };
  if (PAYEE) {
    challengeBody.payee_lightning_address = PAYEE;
  }

  const r1 = await fetch(`${BASE_URL}/v1/paywall/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": API_KEY,
    },
    body: JSON.stringify(challengeBody),
  });
  const data1 = await r1.json();
  console.log("STEP 1 status:", r1.status);
  console.log("STEP 1 body:", data1);

  if (r1.status !== 200) {
    throw new Error("Challenge failed");
  }

  const invoice = data1.invoice;
  const macaroon = data1.macaroon;

  // 2) Pay invoice via NWC
  const ln = new LN(PAYER_NWC);
  const payRes = await ln.pay(invoice);
  const preimage = payRes?.preimage;
  if (!preimage) {
    throw new Error("Payment succeeded but no preimage was returned");
  }
  console.log("STEP 2 preimage:", preimage);

  // 3) Verify (consumes 1 credit)
  const auth = `L402 ${macaroon}:${preimage}`;
  const r3 = await fetch(`${BASE_URL}/v1/paywall/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": API_KEY,
      Authorization: auth,
    },
    body: JSON.stringify({ expected_resource: RESOURCE, cost_credits: 1 }),
  });
  const data3 = await r3.json();
  console.log("STEP 3 status:", r3.status);
  console.log("STEP 3 body:", data3);

  console.log("Balance AFTER:", await getBalance());
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(1);
});
