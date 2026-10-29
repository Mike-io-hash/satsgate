import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { formatAddressBlocks } from '../src/address.js'
import { COPY, ERROR_MESSAGES, GENERIC_ERROR, expirySentence, messageForError } from '../src/copy.js'
import { isUserRejection, phoneSignHint } from '../src/errors.js'
import { utf8ToHex } from '../src/hex.js'
import { isProjectId } from '../src/project.js'
import { readConnectToken, takeConnectToken } from '../src/token.js'

const SAMPLE = '0x4A9E2CA774BB87110ffF3CB8a250e935cFE52Ce3'

describe('connect token', () => {
  test('reads t from the fragment and rejects anything else', () => {
    assert.equal(readConnectToken('#t=sgc_abcDEF-123_zzzzzzzz'), 'sgc_abcDEF-123_zzzzzzzz')
    assert.equal(readConnectToken('#t=sgc_short'), null)
    assert.equal(readConnectToken('#x=sgc_abcDEF-123_zzzzzzzz'), null)
    assert.equal(readConnectToken(''), null)
    assert.equal(readConnectToken('#t=sg_account-key-value-xx'), null)
  })

  test('replaceState drops the hash and keeps the token only as a return value', () => {
    const location = {
      pathname: '/connect/',
      search: '',
      hash: '#t=sgc_abcDEF-123_zzzzzzzz',
    }
    const history = {
      url: '',
      replaceState(_state, _title, url) {
        this.url = url
      },
    }
    const token = takeConnectToken(location, history)
    assert.equal(token, 'sgc_abcDEF-123_zzzzzzzz')
    assert.equal(history.url, '/connect/')
    assert.equal(history.url.includes('#'), false)
    assert.equal(history.url.includes('sgc_'), false)
  })
})

describe('error copy', () => {
  test('every connect error has plain words and an unknown code is generic', () => {
    const expected = {
      stale_challenge: 'The signing window expired. Tap Continue to get a new message.',
      bad_signature: 'The signature does not match this address. Make sure you sign with the same wallet and account you connected.',
      smart_wallet_not_supported:
        'This looks like a smart-contract wallet (for example Safe or Coinbase Smart Wallet). Those are not supported yet. Use a regular wallet address you control.',
      connect_link_invalid:
        'This link is missing, expired, or already used. Ask for a new one with POST /v1/client/payee/evm/connect.',
      rate_limited: 'Too many attempts. Wait a minute and try again.',
      unreachable: 'Satsgate could not be reached. Try again in a minute.',
      cancelled: 'Cancelled. Nothing changed.',
    }
    for (const [code, text] of Object.entries(expected)) {
      assert.equal(messageForError(code), text)
      assert.equal(ERROR_MESSAGES[code], text)
    }
    assert.equal(messageForError('no_such_code'), GENERIC_ERROR)
    assert.equal(messageForError(''), GENERIC_ERROR)
    assert.equal(/anonymous/i.test(JSON.stringify(ERROR_MESSAGES)), false)
  })
})

describe('expiry sentence', () => {
  const stay = 'Keep this tab open. Refreshing forgets the link.'

  test('does not add a second period when the locale already ends with one', () => {
    const cases = [
      '29/10/2026, 6:41:17 p.m.',
      '29/10/2026, 6:41:17 a.m.',
      '29/10/2026, 6:41:17 p. m.',
      '29/10/2026 18:41:17。',
    ]
    for (const when of cases) {
      const line = expirySentence(when)
      assert.equal(line, `This link expires ${when} ${stay}`)
      assert.equal(line.includes('..'), false, line)
    }
  })

  test('keeps a single period when the locale does not end with one', () => {
    const cases = [
      '10/29/2026, 6:41:17 PM',
      '29/10/2026, 18:41:17',
      '29.10.2026, 18:41:17',
    ]
    for (const when of cases) {
      const line = expirySentence(when)
      assert.equal(line, `This link expires ${when}. ${stay}`)
      assert.equal(line.includes('..'), false, line)
    }
  })

  test('no sampled locale formats into a double period', () => {
    const sample = new Date('2026-10-29T18:41:17Z')
    const locales = ['en-US', 'en-GB', 'en-IE', 'en-AU', 'en-CA', 'es-AR', 'es-MX', 'es-ES', 'pt-BR', 'fr-FR', 'de-DE', 'ja-JP', 'ar', 'zh-CN']
    for (const locale of locales) {
      const line = expirySentence(sample.toLocaleString(locale))
      assert.equal(line.includes('..'), false, `${locale}: ${line}`)
      assert.match(line, /^This link expires .+ Keep this tab open\. Refreshing forgets the link\.$/)
    }
  })
})

describe('callout copy', () => {
  test('adds the two titles and the lock without rewriting the exchange body', () => {
    assert.equal(COPY.baseTitle, '✅ USDC on Base only')
    assert.equal(COPY.baseMiddle, 'Buyers pay USDC on the Base network (')
    assert.equal(COPY.exchangeTitle, '⚠️ Do not use an exchange deposit address')
    assert.equal(
      COPY.exchangeBefore,
      'Use an address from a wallet you control, such as MetaMask, Rabby, Coinbase Wallet, Trust Wallet, Rainbow or a hardware wallet. ',
    )
    assert.equal(COPY.exchangeStrong, 'Do not use a deposit address from an exchange')
    assert.equal(
      COPY.exchangeAfter,
      ' (Coinbase.com, Binance, Kraken, OKX and others). Exchanges can change or retire deposit addresses, may not credit USDC sent this way, and you could lose the payments.',
    )
    assert.equal(
      COPY.neverAsk,
      '🔒 Satsgate will never ask for your seed phrase (recovery phrase) or private key. If any page or person does, it is a scam.',
    )
    assert.equal(COPY.verified, 'Verified ✓')
  })
})

describe('personal_sign encoding', () => {
  test('encodes UTF-8 including newlines', () => {
    assert.equal(utf8ToHex('a\nb'), '0x610a62')
    assert.equal(utf8ToHex('Satsgate x402 payee\n'), '0x536174736761746520783430322070617965650a')
  })
})

describe('address read-back', () => {
  test('keeps checksum case and groups the hex in blocks of four', () => {
    assert.equal(formatAddressBlocks(SAMPLE), '0x 4A9E 2CA7 74BB 8711 0ffF 3CB8 a250 e935 cFE5 2Ce3')
    assert.throws(() => formatAddressBlocks(SAMPLE.toLowerCase().slice(0, 10)))
  })
})

describe('project id', () => {
  test('accepts 32 hex characters and rejects anything else', () => {
    assert.equal(isProjectId('a'.repeat(32)), true)
    assert.equal(isProjectId('A'.repeat(32)), true)
    assert.equal(isProjectId(''), false)
    assert.equal(isProjectId('g'.repeat(32)), false)
    assert.equal(isProjectId('ab'), false)
    assert.equal(isProjectId(null), false)
  })
})

describe('sign hints', () => {
  test('asks a laptop user to check the phone only for WalletConnect', () => {
    assert.equal(phoneSignHint('Mozilla/5.0 (X11; Linux x86_64)', 'WALLET_CONNECT'), 'Check your phone: your wallet is asking you to sign.')
    assert.equal(phoneSignHint('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile', 'WALLET_CONNECT'), '')
    assert.equal(phoneSignHint('Mozilla/5.0 (X11; Linux x86_64)', 'INJECTED'), '')
  })

  test('treats a rejected signature as a cancel', () => {
    assert.equal(isUserRejection({ code: 4001 }), true)
    assert.equal(isUserRejection({ code: 'ACTION_REJECTED' }), true)
    assert.equal(isUserRejection({ message: 'User rejected the request' }), true)
    assert.equal(isUserRejection({ message: 'network down' }), false)
  })
})

describe('page source', () => {
  test('does not name a transaction, typed-data, or permission method', async () => {
    const dir = fileURLToPath(new URL('../src/', import.meta.url))
    const names = await walk(dir)
    const forbidden = [
      'eth_sendTransaction',
      'eth_signTypedData',
      'eth_signTypedData_v4',
      'wallet_requestPermissions',
      'localStorage',
      'sessionStorage',
    ]
    for (const name of names) {
      const text = await readFile(name, 'utf8')
      for (const method of forbidden) {
        assert.equal(text.includes(method), false, `${name} contains ${method}`)
      }
      assert.equal(/anonymous/i.test(text), false, `${name} says anonymous`)
    }
    assert.ok(names.length > 0)
  })

  test('styles the approved card without an inline style', async () => {
    const css = await readFile(fileURLToPath(new URL('../src/style.css', import.meta.url)), 'utf8')
    const main = await readFile(fileURLToPath(new URL('../src/main.js', import.meta.url)), 'utf8')
    const tokens = ['#e9eef0', '#f7931a', '#d6f3e4', '#12a36a', '#0b6b46', '#ffe1cc', '#e8590c', '#b23f00', '#e3e7e8']
    for (const token of tokens) assert.equal(css.includes(token), true, token)
    assert.equal(main.includes('expirySentence'), true)
    assert.equal(main.includes('${COPY.stay}'), false)
    assert.equal(main.includes('style='), false)
  })
})

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) files.push(...(await walk(path)))
    else files.push(path)
  }
  return files
}
