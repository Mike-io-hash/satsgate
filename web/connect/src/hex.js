export function utf8ToHex(text) {
  const bytes = new TextEncoder().encode(String(text))
  let hex = '0x'
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}
