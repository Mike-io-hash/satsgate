import './style.css'
import { createAppKit } from '@reown/appkit'
import { EthersAdapter } from '@reown/appkit-adapter-ethers'
import { base } from '@reown/appkit/networks'
import { getAddress } from 'ethers'

import { ApiError, getConfig, getSession, postChallenge, postVerify } from './api.js'
import { formatAddressBlocks } from './address.js'
import {
  BASE_USDC_URL,
  COPY,
  DOCS_URL,
  ERROR_MESSAGES,
  GENERIC_ERROR,
  SEPOLIA_USDC_URL,
  expirySentence,
  messageForError,
} from './copy.js'
import { isUserRejection, phoneSignHint } from './errors.js'
import { utf8ToHex } from './hex.js'
import { isProjectId } from './project.js'
import { takeConnectToken } from './token.js'

const root = document.querySelector('#app')
const state = {
  token: null,
  info: null,
  configured: false,
  view: 'loading',
  account: null,
  providerType: '',
  challenge: null,
  checked: false,
  error: '',
  result: null,
  busy: false,
  modal: null,
}

function h(tag, props, children) {
  const node = document.createElement(tag)
  const fields = props || {}
  for (const [key, value] of Object.entries(fields)) {
    if (key === 'class') node.className = value
    else if (key === 'text') node.textContent = value
    else if (typeof value === 'function') node.addEventListener(key, value)
    else if (value != null) node.setAttribute(key, String(value))
  }
  for (const child of children || []) {
    if (child == null) continue
    node.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
  return node
}

function checksum(value) {
  return getAddress(value)
}

function blocks(value) {
  try {
    return formatAddressBlocks(checksum(value))
  } catch {
    return String(value || '')
  }
}

function localExpiry(unix) {
  if (!unix) return ''
  return new Date(unix * 1000).toLocaleString()
}

function messageFor(error) {
  if (isUserRejection(error)) return messageForError('cancelled')
  if (error instanceof ApiError) {
    if (error.code === 'unreachable' || error.code === 'rate_limited') return messageForError(error.code)
    if (Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, error.code)) return messageForError(error.code)
    if (error.status >= 500 || error.status === 0) return messageForError('unreachable')
    return GENERIC_ERROR
  }
  return messageForError('unreachable')
}

function baseNote() {
  return h('p', { class: 'note' }, [
    h('span', { class: 'title' }, [COPY.baseTitle]),
    COPY.baseMiddle,
    h('a', { href: SEPOLIA_USDC_URL, rel: 'noopener noreferrer' }, [COPY.baseSepolia]),
    COPY.baseBetween,
    h('a', { href: BASE_USDC_URL, rel: 'noopener noreferrer' }, [COPY.baseLive]),
    COPY.baseAfter,
  ])
}

function exchangeNote() {
  return h('p', { class: 'warning' }, [
    h('span', { class: 'title' }, [COPY.exchangeTitle]),
    COPY.exchangeBefore,
    h('strong', {}, [COPY.exchangeStrong]),
    COPY.exchangeAfter,
  ])
}

function currentNote() {
  const address = state.info && state.info.current_payee_evm_address
  if (!state.info || !state.info.current_payee_evm_verified || !address) return null
  return h('p', { class: 'current' }, [
    COPY.currentBefore,
    h('code', { class: 'addr' }, [blocks(address)]),
    '. Connecting a ',
    h('strong', {}, [COPY.different]),
    ' address replaces it and turns USDC off on your sites until you turn it on again. Connecting the same address again changes nothing.',
  ])
}

function footer() {
  return h('footer', {}, [h('p', {}, [COPY.footer])])
}

function errorLine() {
  if (!state.error) return null
  return h('p', { class: 'error', role: 'alert' }, [state.error])
}

function shell(panel) {
  root.replaceChildren(
    h('main', {}, [
      h('p', { class: 'brand' }, ['Satsgate']),
      h('h1', {}, [COPY.title]),
      baseNote(),
      exchangeNote(),
      currentNote(),
      state.info
        ? h('p', { class: 'expiry' }, [expirySentence(localExpiry(state.info.expires_at))])
        : null,
      h('p', { class: 'never' }, [COPY.neverAsk]),
      panel,
      footer(),
    ]),
  )
}

function renderInvalid() {
  root.replaceChildren(
    h('main', {}, [
      h('p', { class: 'brand' }, ['Satsgate']),
      h('h1', {}, ['Connect link']),
      h('p', { class: 'error', role: 'alert' }, [ERROR_MESSAGES.connect_link_invalid]),
      h('p', {}, [h('a', { href: DOCS_URL, rel: 'noopener noreferrer' }, [COPY.docs])]),
      h('p', { class: 'never' }, [COPY.neverAsk]),
      footer(),
    ]),
  )
}

function renderLoading() {
  root.replaceChildren(h('main', {}, [h('p', {}, [COPY.loading])]))
}

function renderReady() {
  const button = h(
    'button',
    {
      type: 'button',
      class: 'primary',
      disabled: state.configured ? null : '',
      click: () => {
        if (state.modal) state.modal.open()
      },
    },
    [COPY.connect],
  )
  if (!state.configured) button.disabled = true
  shell(
    h('section', {}, [
      state.configured ? null : h('p', { class: 'error', role: 'alert' }, [COPY.unconfigured]),
      errorLine(),
      button,
    ]),
  )
}

async function copyAddress(address, button) {
  try {
    await navigator.clipboard.writeText(checksum(address))
    button.textContent = COPY.copied
  } catch {
    button.textContent = COPY.copy
  }
}

function renderConfirm() {
  const address = state.account && state.account.address
  const box = h('input', { type: 'checkbox', id: 'own-wallet' })
  box.checked = state.checked
  box.addEventListener('change', () => {
    state.checked = box.checked
    const next = root.querySelector('#continue')
    if (next) next.disabled = !state.checked || state.busy
  })
  const copy = h('button', { type: 'button', class: 'ghost' }, [COPY.copy])
  copy.addEventListener('click', () => copyAddress(address, copy))
  const go = h(
    'button',
    {
      type: 'button',
      id: 'continue',
      class: 'primary',
      click: () => requestChallenge(),
    },
    [COPY.continue],
  )
  go.disabled = !state.checked || state.busy
  shell(
    h('section', {}, [
      h('p', {}, [COPY.question]),
      h('p', { class: 'addr' }, [blocks(address)]),
      copy,
      h('label', { class: 'check' }, [box, h('span', {}, [COPY.checkbox])]),
      errorLine(),
      go,
    ]),
  )
}

function renderReview() {
  const hint = phoneSignHint(navigator.userAgent, state.providerType)
  const message = h('textarea', { readonly: '', rows: '8' })
  message.value = state.challenge ? state.challenge.message : ''
  const sign = h(
    'button',
    { type: 'button', class: 'primary', click: () => signMessage() },
    [COPY.sign],
  )
  sign.disabled = state.busy
  const again = h(
    'button',
    { type: 'button', class: 'ghost', click: () => requestChallenge() },
    [COPY.continue],
  )
  again.disabled = state.busy
  shell(
    h('section', {}, [
      h('p', {}, [COPY.signing]),
      message,
      hint ? h('p', { class: 'hint' }, [hint]) : null,
      errorLine(),
      state.error === ERROR_MESSAGES.stale_challenge ? again : null,
      state.error === ERROR_MESSAGES.smart_wallet_not_supported
        ? h('button', { type: 'button', class: 'ghost', click: () => state.modal && state.modal.open() }, [COPY.otherWallet])
        : null,
      sign,
    ]),
  )
}

function renderSuccess() {
  const address = state.result && state.result.payee_evm_address
  shell(
    h('section', {}, [
      h('h2', {}, [COPY.verified]),
      h('p', { class: 'addr verified' }, [blocks(address)]),
      state.result && state.result.rails_cleared ? h('p', { class: 'warning' }, [COPY.railsCleared]) : null,
      h('p', {}, [COPY.closePage]),
    ]),
  )
}

function renderMismatch() {
  shell(
    h('section', {}, [
      h('p', { class: 'error', role: 'alert' }, [COPY.mismatch]),
      h('p', {}, [COPY.closePage]),
    ]),
  )
}

function renderProblem() {
  shell(
    h('section', {}, [
      errorLine(),
      h('button', { type: 'button', class: 'primary', click: () => loadSession() }, [COPY.tryAgain]),
    ]),
  )
}

function render() {
  if (state.view === 'loading') renderLoading()
  else if (state.view === 'invalid') renderInvalid()
  else if (state.view === 'problem') renderProblem()
  else if (state.view === 'confirm') renderConfirm()
  else if (state.view === 'review') renderReview()
  else if (state.view === 'success') renderSuccess()
  else if (state.view === 'mismatch') renderMismatch()
  else renderReady()
}

async function requestChallenge() {
  if (!state.token || !state.account || !state.account.address) return
  state.busy = true
  state.error = ''
  render()
  try {
    const address = checksum(state.account.address)
    state.challenge = await postChallenge(state.token, address)
    state.view = 'review'
    state.providerType = state.modal ? state.modal.getProviderType('eip155') || '' : ''
  } catch (error) {
    applyError(error)
  } finally {
    state.busy = false
    render()
  }
}

async function signMessage() {
  if (!state.token || !state.modal || !state.challenge) return
  const provider = state.modal.getProvider('eip155')
  const address = checksum(state.account.address)
  state.providerType = state.modal.getProviderType('eip155') || ''
  if (!provider) {
    state.error = messageForError('unreachable')
    render()
    return
  }
  state.busy = true
  state.error = ''
  render()
  try {
    const signature = await provider.request({
      method: 'personal_sign',
      params: [utf8ToHex(state.challenge.message), address],
    })
    const result = await postVerify(state.token, address, signature)
    let server = ''
    try {
      server = checksum(result.payee_evm_address)
    } catch {
      server = ''
    }
    state.token = null
    state.result = result
    state.view = server.toLowerCase() === address.toLowerCase() ? 'success' : 'mismatch'
  } catch (error) {
    applyError(error)
  } finally {
    state.busy = false
    render()
  }
}

function applyError(error) {
  if (error instanceof ApiError && error.code === 'connect_link_invalid') {
    state.token = null
    state.view = 'invalid'
    state.error = ''
    return
  }
  state.error = messageFor(error)
}

function setupModal(projectId) {
  state.modal = createAppKit({
    adapters: [new EthersAdapter()],
    networks: [base],
    projectId,
    metadata: {
      name: 'Satsgate',
      description: 'Verify the address that receives USDC on Base.',
      url: 'https://satsgate.org',
      icons: ['https://satsgate.org/connect/icon.svg'],
    },
    coinbasePreference: 'eoaOnly',
    defaultAccountTypes: { eip155: 'eoa' },
    allowUnsupportedChain: true,
    enableNetworkSwitch: false,
    enableReconnect: false,
    features: {
      analytics: false,
      swaps: false,
      onramp: false,
      email: false,
      socials: false,
      history: false,
      send: false,
      receive: false,
      pay: false,
      smartSessions: false,
      reownAuthentication: false,
      connectMethodsOrder: ['wallet'],
    },
  })
  state.modal.subscribeAccount((account) => {
    state.account = account
    const connected = Boolean(account && account.isConnected && account.address)
    if (connected && state.view === 'ready') state.view = 'confirm'
    if (!connected && state.view === 'confirm') {
      state.view = 'ready'
      state.checked = false
    }
    if (state.view === 'ready' || state.view === 'confirm') render()
  })
}

async function loadSession() {
  state.view = 'loading'
  state.error = ''
  render()
  try {
    state.info = await getSession(state.token)
  } catch (error) {
    applyError(error)
    if (state.view !== 'invalid') state.view = 'problem'
    render()
    return
  }
  let config = null
  try {
    config = await getConfig()
  } catch {
    config = null
  }
  const projectId = config && isProjectId(config.projectId) ? config.projectId : ''
  state.configured = Boolean(projectId)
  if (projectId && !state.modal) setupModal(projectId)
  state.view = 'ready'
  render()
}

async function boot() {
  state.token = takeConnectToken(window.location, window.history)
  render()
  if (!state.token) {
    state.view = 'invalid'
    render()
    return
  }
  await loadSession()
}

boot()
