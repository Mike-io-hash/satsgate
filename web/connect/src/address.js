export function formatAddressBlocks(address) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new TypeError('invalid address')
  }
  const groups = address.slice(2).match(/.{4}/g)
  return `0x ${groups.join(' ')}`
}
