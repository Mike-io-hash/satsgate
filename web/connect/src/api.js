import { ApiError } from './api-error.js'

export { ApiError }

async function request(path, { method = 'GET', token, body } = {}) {
  let response
  try {
    response = await fetch(path, {
      method,
      cache: 'no-store',
      headers: {
        'X-Connect-Token': token,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError('unreachable', 0)
  }
  let payload = null
  try {
    payload = await response.json()
  } catch {
    payload = null
  }
  if (response.status === 429) throw new ApiError('rate_limited', 429)
  if (response.status >= 500) throw new ApiError('unreachable', response.status)
  if (!response.ok) {
    const code = payload && typeof payload.error === 'string' ? payload.error : 'unknown'
    throw new ApiError(code, response.status)
  }
  return payload
}

export function getConfig() {
  return fetch('/connect/config.json', { cache: 'no-store' }).then(async (response) => {
    if (!response.ok) throw new Error('config')
    return response.json()
  })
}

export function getSession(token) {
  return request('/v1/connect/evm', { token })
}

export function postChallenge(token, address) {
  return request('/v1/connect/evm/challenge', { method: 'POST', token, body: { address } })
}

export function postVerify(token, address, signature) {
  return request('/v1/connect/evm/verify', { method: 'POST', token, body: { address, signature } })
}
