import Card from './Card.jsx'
import { ACTIVE_STATES } from '../services/api.js'
import { formatSeconds } from '../services/format.js'

const STATE_LABELS = {
  uploaded: 'Uploaded',
  queued: 'Queued',
  running: 'Analyzing',
  completed: 'Completed',
  completed_with_errors: 'Completed with errors',
  failed: 'Failed',
}

const STATE_COLORS = {
  running: 'bg-violet-100 text-violet-800',
  queued: 'bg-slate-100 text-slate-700',
  completed: 'bg-emerald-100 text-emerald-800',
  completed_with_errors: 'bg-amber-100 text-amber-900',
  failed: 'bg-red-100 text-red-800',
}

function Stat({ label, value }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="text-sm font-medium tabular-nums">{value}</dd>
    </div>
  )
}

export default function StatusPanel({ status, error, onResume }) {
  if (!status) {
    return (
      <Card title="2. Progress">
        <p className="text-sm text-slate-500">{error || 'No analysis yet. Upload a log to begin.'}</p>
      </Card>
    )
  }
  const { state, total_chunks: total, chunks_done: done, ram_mb: ram } = status
  const percent = total ? Math.round((done / total) * 100) : 0
  const canResume = ['failed', 'completed_with_errors'].includes(state)

  return (
    <Card
      title="2. Progress"
      action={<span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${STATE_COLORS[state] || ''}`}>{STATE_LABELS[state] || state}</span>}
    >
      <p className="truncate text-sm text-slate-600" title={status.filename}>{status.filename}</p>
      <div className="mt-3 h-2.5 w-full overflow-hidden rounded-full bg-slate-100" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full bg-violet-600 transition-all" style={{ width: `${percent}%` }} />
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3">
        <Stat label="Chunk" value={total ? `${Math.min(status.current_chunk, total)} / ${total}` : '–'} />
        <Stat label="Entries processed" value={`${status.entries_processed} / ${status.total_entries || '–'}`} />
        <Stat label="Elapsed" value={formatSeconds(status.elapsed_s)} />
        <Stat label="Failed chunks" value={status.chunks_failed} />
        <Stat label="RAM (model)" value={ram ? `${ram.model} MB` : '–'} />
        <Stat label="RAM (backend)" value={ram ? `${ram.backend} MB` : '–'} />
      </dl>
      <p className="mt-3 text-xs text-slate-500">Model: {status.model}</p>
      {ACTIVE_STATES.includes(state) && (
        <p className="mt-2 text-xs text-slate-500">One chunk takes about 20–30 s on CPU.</p>
      )}
      {status.error && <p role="alert" className="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{status.error}</p>}
      {error && <p role="alert" className="mt-3 rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-800">{error}</p>}
      {canResume && (
        <button type="button" onClick={onResume}
          className="mt-4 w-full rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium hover:bg-slate-50">
          Retry failed chunks
        </button>
      )}
    </Card>
  )
}
