const CONNECT = /^sgc_[A-Za-z0-9_-]{16,128}$/
const EMAIL = /^sge_[A-Za-z0-9_-]{16,128}$/

function readToken(hash, pattern) {
  const raw = String(hash || '')
  const body = raw.startsWith('#') ? raw.slice(1) : raw
  if (!body) return null
  const token = new URLSearchParams(body).get('t')
  if (!token || !pattern.test(token)) return null
  return token
}

export function readConnectToken(hash) {
  return readToken(hash, CONNECT)
}

export function readEmailToken(hash) {
  return readToken(hash, EMAIL)
}

export function isEmailConfirmPath(pathname) {
  return /\/confirm-email\/?$/.test(String(pathname || ''))
}

function takeFragment(location, history, read) {
  const token = read(location.hash || '')
  const path = `${location.pathname || '/'}${location.search || ''}`
  history.replaceState(null, '', path)
  return token
}

export function takeConnectToken(location, history) {
  return takeFragment(location, history, readConnectToken)
}

export function takeEmailToken(location, history) {
  return takeFragment(location, history, readEmailToken)
}
