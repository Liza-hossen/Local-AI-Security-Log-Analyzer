// Thin wrappers around the FastAPI endpoints. Every call throws an Error with a
// readable message (the backend's "detail" when there is one), so components
// only need one try/catch.
const BASE = '/api'

async function request(path, options = {}) {
  let response
  try {
    response = await fetch(BASE + path, options)
  } catch {
    throw new Error('Cannot reach the backend. Is it running on port 8000?')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = body && body.detail
    throw new Error(typeof detail === 'string' ? detail : `Request failed (${response.status})`)
  }
  return body
}

export function uploadLog(file) {
  const form = new FormData()
  form.append('file', file)
  return request('/upload', { method: 'POST', body: form })
}

export const startAnalysis = (jobId, restart = false) =>
  request(`/analyze/${jobId}${restart ? '?restart=true' : ''}`, { method: 'POST' })
export const getStatus = (jobId) => request(`/status/${jobId}`)
export const getFindings = (jobId) => request(`/findings/${jobId}`)
export const getReport = (jobId) => request(`/report/${jobId}`)
export const getLines = (jobId, numbers) => request(`/lines/${jobId}?numbers=${numbers.join(',')}`)
export const downloadUrl = (jobId) => `${BASE}/report/${jobId}/download`

export const ACTIVE_STATES = ['queued', 'running']
export const FINISHED_STATES = ['completed', 'completed_with_errors']
