export function isProjectId(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{32}$/.test(value)
}
