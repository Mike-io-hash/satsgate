export const DOCS_URL = 'https://github.com/Mike-io-hash/satsgate#hosted-gate-x402'

export const SEPOLIA_USDC_URL = 'https://sepolia.basescan.org/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e'
export const BASE_USDC_URL = 'https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'

export const COPY = {
  title: 'Connect the wallet that will receive USDC on Base',
  baseTitle: '✅ USDC on Base only',
  baseMiddle: 'Buyers pay USDC on the Base network (',
  baseSepolia: 'Base Sepolia',
  baseBetween: ' while a site is in test mode, ',
  baseLive: 'Base',
  baseAfter: ' when the site is live). USDC sent on Ethereum, Polygon, Solana, Arbitrum or any other network is not accepted.',
  exchangeTitle: '⚠️ Do not use an exchange deposit address',
  exchangeBefore: 'Use an address from a wallet you control, such as MetaMask, Rabby, Coinbase Wallet, Trust Wallet, Rainbow or a hardware wallet. ',
  exchangeStrong: 'Do not use a deposit address from an exchange',
  exchangeAfter: ' (Coinbase.com, Binance, Kraken, OKX and others). Exchanges can change or retire deposit addresses, may not credit USDC sent this way, and you could lose the payments.',
  neverAsk: '🔒 Satsgate will never ask for your seed phrase (recovery phrase) or private key. If any page or person does, it is a scam.',
  footer: 'Satsgate is non-custodial: buyers pay this address directly and Satsgate never holds your funds. No KYC.',
  currentBefore: 'Your current address is ',
  currentAfter: '. Connecting a different address replaces it and turns USDC off on your sites until you turn it on again. Connecting the same address again changes nothing.',
  different: 'different',
  checkbox: 'This is a wallet I control on Base. It is not an exchange deposit address.',
  question: 'Is this the address where you want to receive USDC on Base?',
  signing: 'Signing is free. It does not send a transaction or move funds.',
  connect: 'Connect wallet',
  continue: 'Continue',
  sign: 'Sign',
  copy: 'Copy',
  copied: 'Copied',
  stay: 'Keep this tab open. Refreshing forgets the link.',
  unconfigured: 'Wallet connection is not configured yet.',
  verified: 'Verified ✓',
  railsCleared: 'USDC was turned off on your sites because the address changed. Turn it back on with PATCH /v1/sites/{slug}.',
  closePage: 'You can close this page. This link no longer works.',
  mismatch: 'The verified address does not match the wallet you connected.',
  docs: 'How to create a connect link',
  loading: 'Checking this link…',
  tryAgain: 'Try again',
  otherWallet: 'Use a different wallet',
}

export const ERROR_MESSAGES = {
  stale_challenge: 'The signing window expired. Tap Continue to get a new message.',
  bad_signature: 'The signature does not match this address. Make sure you sign with the same wallet and account you connected.',
  smart_wallet_not_supported: 'This looks like a smart-contract wallet (for example Safe or Coinbase Smart Wallet). Those are not supported yet. Use a regular wallet address you control.',
  connect_link_invalid: 'This link is missing, expired, or already used. Ask for a new one with POST /v1/client/payee/evm/connect.',
  rate_limited: 'Too many attempts. Wait a minute and try again.',
  unreachable: 'Satsgate could not be reached. Try again in a minute.',
  cancelled: 'Cancelled. Nothing changed.',
}

export const GENERIC_ERROR = 'Something went wrong. Nothing was changed. Try again.'

export function messageForError(code) {
  if (Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code)) return ERROR_MESSAGES[code]
  return GENERIC_ERROR
}

// A locale time such as "6:41:17 p.m." already ends with a period. The
// sentence adds one only when the formatted value does not.
const ALREADY_CLOSES = /[.。．]$/

export function expirySentence(when) {
  const text = String(when ?? '').trim()
  if (!text) return `This link expires . ${COPY.stay}`
  const gap = ALREADY_CLOSES.test(text) ? ' ' : '. '
  return `This link expires ${text}${gap}${COPY.stay}`
}
