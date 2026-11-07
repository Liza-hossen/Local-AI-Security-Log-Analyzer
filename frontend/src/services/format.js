// Small display helpers shared by components.

export const SEVERITY_STYLES = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-amber-300 text-amber-950',
  Low: 'bg-sky-100 text-sky-800 ring-1 ring-sky-300',
}

export const SEVERITY_BAR = {
  Critical: 'bg-red-600',
  High: 'bg-orange-500',
  Medium: 'bg-amber-400',
  Low: 'bg-sky-400',
}

export const STATUS_STYLES = {
  Blocked: 'text-emerald-700 bg-emerald-50 ring-emerald-200',
  Attempted: 'text-slate-700 bg-slate-100 ring-slate-200',
  'Possibly Successful': 'text-red-700 bg-red-50 ring-red-200',
}

export function formatSeconds(total) {
  const s = Math.round(total || 0)
  const m = Math.floor(s / 60)
  return m ? `${m}m ${s % 60}s` : `${s}s`
}

export function lineList(evidence, max = 6) {
  const lines = evidence.map((e) => `L${e.line}`)
  return lines.length > max ? `${lines.slice(0, max).join(', ')} +${lines.length - max}` : lines.join(', ')
}

// Remembering the last job is a per-browser convenience only; storage may be blocked.
export function rememberJob(jobId) {
  try {
    if (jobId) localStorage.setItem('lastJobId', jobId)
    else localStorage.removeItem('lastJobId')
  } catch {
    /* storage unavailable: nothing to do */
  }
}

export function recallJob() {
  const fromUrl = new URLSearchParams(window.location.search).get('job')
  if (fromUrl) return fromUrl
  try {
    return localStorage.getItem('lastJobId') || ''
  } catch {
    return ''
  }
}
