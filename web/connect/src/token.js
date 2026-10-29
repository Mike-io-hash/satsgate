const TOKEN = /^sgc_[A-Za-z0-9_-]{16,128}$/

export function readConnectToken(hash) {
  const raw = String(hash || '')
  const body = raw.startsWith('#') ? raw.slice(1) : raw
  if (!body) return null
  const token = new URLSearchParams(body).get('t')
  if (!token || !TOKEN.test(token)) return null
  return token
}

export function takeConnectToken(location, history) {
  const token = readConnectToken(location.hash || '')
  const path = `${location.pathname || '/'}${location.search || ''}`
  history.replaceState(null, '', path)
  return token
}
