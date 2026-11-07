import { SEVERITY_STYLES, STATUS_STYLES } from '../services/format.js'

export function SeverityBadge({ severity }) {
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[severity] || ''}`}>
      {severity}
    </span>
  )
}

export function StatusBadge({ status }) {
  return (
    <span className={`inline-block whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${STATUS_STYLES[status] || ''}`}>
      {status}
    </span>
  )
}

// Where the finding came from: the local model or a deterministic rule.
export function SourceBadge({ source }) {
  const isModel = source === 'model'
  return (
    <span
      title={isModel ? 'Reported by the local AI model' : 'Added by rule-based detection / correlation'}
      className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-medium ${
        isModel ? 'bg-violet-50 text-violet-700' : 'bg-slate-100 text-slate-600'
      }`}
    >
      {isModel ? 'AI' : 'Rules'}
    </span>
  )
}
