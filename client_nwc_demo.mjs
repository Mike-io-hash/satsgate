// Test client (NWC payer mode)
//
// Flow:
// 1) GET /v1/tickets -> 402 + { invoice, macaroon }
// 2) Pay invoice via Nostr Wallet Connect (NIP-47) using @getalby/sdk
// 3) Retry with Authorization: L402 <macaroon>:<preimage>
//
// Requirements:
// - server running at http://127.0.0.1:8000
// - SATSGATE_WALLET_MODE=lnaddr (to generate a real invoice)
// - a *payer* wallet with NWC (can be different from your Wallet of Satoshi)
// - export SATSGATE_TEST_PAYER_NWC with your connection string (DO NOT paste it in chats)
//
// Install:
//   npm init -y
//   npm install @getalby/sdk
//
// Usage:
//   SATSGATE_TEST_PAYER_NWC='nostr+walletconnect://...' node client_nwc_demo.mjs

import { LN } from "@getalby/sdk";

const BASE_URL = (process.env.SATSGATE_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const CREDENTIALS = process.env.SATSGATE_TEST_PAYER_NWC;

if (!CREDENTIALS) {
  console.error("Missing SATSGATE_TEST_PAYER_NWC (nostr+walletconnect://...)");
  process.exit(2);
}

async function main() {
  // 1) request challenge
  const r1 = await fetch(`${BASE_URL}/v1/tickets`);
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
  // @getalby/sdk returns { preimage, ... } on success
  const preimage = payRes?.preimage;
  if (!preimage) {
    throw new Error("Payment succeeded but no preimage was returned (does your NWC wallet support it?)");
  }
  console.log("STEP 2 preimage:", preimage);

  // 3) retry with auth
  const auth = `L402 ${macaroon}:${preimage}`;
  const r3 = await fetch(`${BASE_URL}/v1/tickets`, {
    headers: { Authorization: auth },
  });
  const data3 = await r3.json();
  console.log("STEP 3 status:", r3.status);
  console.log("STEP 3 body:", data3);
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(1);
});
