// Manual mainnet check for Alby fetch402. This spends sats.
//
//   npm install @getalby/lightning-tools
//   export NWC_CONNECTION_STRING='nostr+walletconnect://...'
//   node mcp/scripts/fetch402.mjs https://your-proxy.example/blog/post
//
// The package reads the wallet from the environment. Do not pass the URI as an argument.
// If the import path differs in the version you installed, the error names the package README.

const url = process.argv[2];
if (!url) {
  console.error("Usage: node mcp/scripts/fetch402.mjs <url>");
  process.exit(2);
}

let fetch402;
try {
  ({ fetch402 } = await import("@getalby/lightning-tools"));
} catch {
  try {
    ({ fetch402 } = await import("@getalby/lightning-tools/fetch402"));
  } catch (error) {
    console.error("Install @getalby/lightning-tools and check its fetch402 export.");
    console.error(error instanceof Error ? error.message : "import failed");
    process.exit(1);
  }
}

const response = await fetch402(url);
console.log(response.status);
const text = await response.text();
console.log(text.slice(0, 4000));
