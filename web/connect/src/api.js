import { ApiError } from './api-error.js'

export { ApiError }

async function request(path, { method = 'GET', token, emailToken, body } = {}) {
  let response
  try {
    response = await fetch(path, {
      method,
      cache: 'no-store',
      headers: {
        ...(token ? { 'X-Connect-Token': token } : {}),
        ...(emailToken ? { 'X-Email-Token': emailToken } : {}),
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

export function postAlertEmail(token, email) {
  return request('/v1/connect/alert-email', { method: 'POST', token, body: { email } })
}

export function getEmailPreview(emailToken) {
  return request('/v1/connect/alert-email', { emailToken })
}

export function postEmailConfirm(emailToken) {
  return request('/v1/connect/alert-email/confirm', { method: 'POST', emailToken })
}
