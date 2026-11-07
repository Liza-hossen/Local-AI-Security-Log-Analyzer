import { useEffect, useState } from 'react'
import { SeverityBadge, SourceBadge, StatusBadge } from './Badges.jsx'
import { getLines } from '../services/api.js'

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm">{children}</dd>
    </div>
  )
}

// Modal with the full explanation and the raw text of every evidence line.
export default function FindingDetail({ finding, jobId, onClose }) {
  const [raw, setRaw] = useState({})
  const [lineError, setLineError] = useState('')

  useEffect(() => {
    const numbers = finding.evidence.map((e) => e.line)
    getLines(jobId, numbers)
      .then((res) => setRaw(Object.fromEntries(res.lines.map((l) => [l.line, l.text]))))
      .catch((e) => setLineError(e.message))
  }, [finding, jobId])

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-20 flex items-end justify-center bg-slate-900/40 sm:items-center sm:p-6" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={`${finding.attack_type} details`}
        onClick={(e) => e.stopPropagation()}
        className="max-h-[92vh] w-full max-w-3xl overflow-y-auto rounded-t-2xl bg-white p-5 shadow-xl sm:rounded-2xl sm:p-6"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
              <SourceBadge source={finding.source} />
            </div>
            <h3 className="mt-2 text-lg font-semibold">{finding.attack_type} from <span className="font-mono">{finding.source_ip || 'unknown IP'}</span></h3>
          </div>
          <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-slate-500 hover:bg-slate-100" aria-label="Close">✕</button>
        </div>

        {finding.corroborated === false && (
          <p className="mt-3 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-800">
            No rule-based signal supports this model finding. It was lowered to Low and needs manual review.
          </p>
        )}

        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label="Explanation"><p className="text-slate-700">{finding.reason}</p></Field>
          <Field label="Suggested action"><p className="text-slate-700">{finding.suggested_action}</p></Field>
          <Field label="Confidence">{Math.round(finding.confidence * 100)}%</Field>
          <Field label="Chunks">{finding.chunk_indexes?.length ? finding.chunk_indexes.join(', ') : '–'}</Field>
        </dl>

        <h4 className="mt-6 text-sm font-semibold">Evidence ({finding.evidence.length} lines)</h4>
        {lineError && <p className="mt-1 text-xs text-amber-700">Could not load raw lines: {lineError}</p>}
        <ul className="mt-2 space-y-2">
          {finding.evidence.map((e) => (
            <li key={e.line} className="rounded-lg border border-slate-200 p-3">
              <div className="flex flex-wrap items-baseline gap-2 text-sm">
                <span className="rounded bg-slate-900 px-1.5 py-0.5 font-mono text-xs text-white">L{e.line}</span>
                <span className="text-slate-700">{e.description}</span>
              </div>
              {raw[e.line] && (
                <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-2 font-mono text-[11px] text-slate-600">{raw[e.line]}</pre>
              )}
            </li>
          ))}
        </ul>

        {finding.notes?.length > 0 && (
          <>
            <h4 className="mt-6 text-sm font-semibold">What the correlation step changed</h4>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-600">
              {finding.notes.map((n, i) => <li key={i}>{n}</li>)}
            </ul>
          </>
        )}
      </div>
    </div>
  )
}
