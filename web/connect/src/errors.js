export function isUserRejection(error) {
  const code = error && error.code
  if (code === 4001 || code === 'ACTION_REJECTED') return true
  const message = String((error && error.message) || '').toLowerCase()
  return message.includes('user rejected') || message.includes('user denied')
}

export function phoneSignHint(userAgent, providerType) {
  const phone = /Android|iPhone|iPad|iPod|Mobile/i.test(String(userAgent || ''))
  if (!phone && providerType === 'WALLET_CONNECT') {
    return 'Check your phone: your wallet is asking you to sign.'
  }
  return ''
}
