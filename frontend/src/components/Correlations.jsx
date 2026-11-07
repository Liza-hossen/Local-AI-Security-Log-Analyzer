import { SeverityBadge } from './Badges.jsx'

// One card per multi-step attack story, with its stages as a vertical timeline.
export default function Correlations({ correlations }) {
  if (!correlations.length) {
    return <p className="text-sm text-slate-500">No multi-step attack sequences were detected.</p>
  }
  return (
    <div className="space-y-4">
      {correlations.map((c) => (
        <div key={`${c.source_ip}-${c.kind}`} className="rounded-lg border border-red-200 bg-red-50/40 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={c.severity} />
            <span className="font-semibold">{c.kind.replaceAll('_', ' ')}</span>
            <span className="font-mono text-sm">{c.source_ip}</span>
            {c.chunk_indexes.length > 1 && (
              <span className="rounded bg-white px-2 py-0.5 text-xs text-slate-600 ring-1 ring-slate-200">
                spans {c.chunk_indexes.length} chunks ({c.chunk_indexes.join(', ')})
              </span>
            )}
          </div>
          <p className="mt-2 text-sm text-slate-700">{c.description}</p>
          <ol className="mt-3 space-y-2 border-l-2 border-red-300 pl-4">
            {c.stages.map((s, i) => (
              <li key={s.name} className="text-sm">
                <span className="font-medium">{i + 1}. {s.name}</span>
                <span className="text-slate-500"> ×{s.count}</span>
                <div className="font-mono text-xs text-slate-600">{s.lines.map((n) => `L${n}`).join(', ')}{s.count > s.lines.length ? ' …' : ''}</div>
              </li>
            ))}
          </ol>
        </div>
      ))}
    </div>
  )
}
