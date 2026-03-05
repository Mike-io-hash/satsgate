// Automated end-to-end tester for a *customer* paywalled endpoint.
//
// It calls a paywalled endpoint without Authorization (expects 402), pays the returned invoice via NWC,
// then retries with Authorization: L402 <macaroon>:<preimage>.
//
// Requirements:
// - Node.js 18+
// - `npm install` at repo root (installs @getalby/sdk)
// - env: TEST_PAYER_NWC='nostr+walletconnect://...'
//
// Usage:
//   TEST_PAYER_NWC='nostr+walletconnect://...' node payer_nwc.mjs http://127.0.0.1:9000/premium
//
import { LN } from "@getalby/sdk";

const URL = process.argv[2];
if (!URL) {
  console.error("Missing URL argument. Example: http://127.0.0.1:9000/premium");
  process.exit(2);
}

const NWC = process.env.TEST_PAYER_NWC;
if (!NWC) {
  console.error("Missing TEST_PAYER_NWC (nostr+walletconnect://...)");
  process.exit(2);
}

async function main() {
  // 1) request challenge
  const r1 = await fetch(URL);
  const body1 = await r1.json().catch(() => ({}));
  console.log("STEP 1 status:", r1.status);
  console.log("STEP 1 body:", body1);

  if (r1.status !== 402) {
    throw new Error("Expected 402 Payment Required");
  }

  const invoice = body1.invoice;
  const macaroon = body1.macaroon;

  if (!invoice || !macaroon) {
    throw new Error("Missing invoice/macaroon in response body");
  }

  // 2) pay invoice via NWC
  const ln = new LN(NWC);
  const payRes = await ln.pay(invoice);
  const preimage = payRes?.preimage;

  if (!preimage) {
    throw new Error("Payment succeeded but no preimage was returned");
  }

  console.log("STEP 2 preimage:", preimage);

  // 3) retry with Authorization
  const auth = `L402 ${macaroon}:${preimage}`;
  const r3 = await fetch(URL, { headers: { Authorization: auth } });
  const body3 = await r3.json().catch(() => ({}));
  console.log("STEP 3 status:", r3.status);
  console.log("STEP 3 body:", body3);

  // 4) optional: repeat to show cache/idempotency behavior
  const repeat = parseInt(process.env.REPEAT || "0", 10);
  if (repeat > 0) {
    for (let i = 0; i < repeat; i++) {
      const rx = await fetch(URL, { headers: { Authorization: auth } });
      const bx = await rx.json().catch(() => ({}));
      console.log(`REPEAT ${i + 1}/${repeat} status:`, rx.status);
      console.log(`REPEAT ${i + 1}/${repeat} body:`, bx);
    }
  }
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(1);
});
