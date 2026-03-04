// Credit top-up (plan) paid via NWC.
//
// Flow:
// 1) GET /v1/topup/{planId} -> 402 + invoice + macaroon
// 2) Pay invoice via NWC (CoinOS/Alby/etc) -> get preimage
// 3) Retry GET /v1/topup/{planId} with Authorization: L402 <macaroon>:<preimage>
//    -> credits are added and api_key is returned (if this is a new client)
//
// Usage:
//   # If you DON'T pass SATSGATE_CLIENT_API_KEY, it creates a new client and returns api_key
//   SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' node client_topup_nwc.mjs trial
//
//   # If you already have api_key, you can top up the same client:
//   SATSGATE_CLIENT_API_KEY='sg_...' SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' node client_topup_nwc.mjs trial
//
import { LN } from "@getalby/sdk";

const BASE_URL = (process.env.SATSGATE_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const CREDENTIALS = process.env.SATSGATE_TEST_PAYER_NWC;
const API_KEY = process.env.SATSGATE_CLIENT_API_KEY;
const PLAN_ID = process.argv[2] || "trial";

if (!CREDENTIALS) {
  console.error("Missing SATSGATE_TEST_PAYER_NWC (nostr+walletconnect://...)");
  process.exit(2);
}

async function main() {
  // 1) request topup challenge
  const h1 = API_KEY ? { "X-Api-Key": API_KEY } : {};
  const r1 = await fetch(`${BASE_URL}/v1/topup/${encodeURIComponent(PLAN_ID)}`, { headers: h1 });
  const data1 = await r1.json();
  console.log("STEP 1 status:", r1.status);
  console.log("STEP 1 body:", data1);

  if (r1.status !== 402) {
    throw new Error("Expected 402 Payment Required");
  }

  const invoice = data1.invoice;
  const macaroon = data1.macaroon;

  // 2) pay invoice using NWC
  const ln = new LN(CREDENTIALS);
  const payRes = await ln.pay(invoice);
  const preimage = payRes?.preimage;
  if (!preimage) {
    throw new Error("Payment succeeded but no preimage was returned (does your NWC wallet support it?)");
  }
  console.log("STEP 2 preimage:", preimage);

  // 3) finalize topup
  const auth = `L402 ${macaroon}:${preimage}`;
  const h3 = API_KEY ? { "X-Api-Key": API_KEY } : {};
  const r3 = await fetch(`${BASE_URL}/v1/topup/${encodeURIComponent(PLAN_ID)}`, {
    headers: { Authorization: auth, ...h3 },
  });
  const data3 = await r3.json();
  console.log("STEP 3 status:", r3.status);
  console.log("STEP 3 body:", data3);
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(1);
});
