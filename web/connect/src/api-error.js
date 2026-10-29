export class ApiError extends Error {
  constructor(code, status) {
    super(code || 'unknown')
    this.name = 'ApiError'
    this.code = code || 'unknown'
    this.status = status
  }
}
