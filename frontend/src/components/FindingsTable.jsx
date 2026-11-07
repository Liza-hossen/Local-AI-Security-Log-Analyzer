import Card from './Card.jsx'
import { SeverityBadge, SourceBadge, StatusBadge } from './Badges.jsx'
import { lineList } from '../services/format.js'

export default function FindingsTable({ findings, final, running, onSelect }) {
  const note = final
    ? 'Final results after correlation. Click a row for details.'
    : running
      ? 'Live model findings so far. Correlation runs when all chunks are done.'
      : 'Findings appear here during analysis.'

  return (
    <Card title={`3. Findings (${findings.length})`}>
      <p className="-mt-2 mb-3 text-xs text-slate-500">{note}</p>
      {findings.length === 0 ? (
        <p className="py-6 text-center text-sm text-slate-500">{running ? 'Nothing reported yet…' : 'No findings.'}</p>
      ) : (
        <div className="-mx-4 overflow-x-auto sm:mx-0">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Attack</th>
                <th className="px-3 py-2 font-medium">Source IP</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Lines</th>
                <th className="px-3 py-2 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr
                  key={`${f.source_ip}-${f.attack_type}-${i}`}
                  onClick={() => onSelect(f)}
                  onKeyDown={(e) => e.key === 'Enter' && onSelect(f)}
                  tabIndex={0}
                  className={`cursor-pointer border-b border-slate-100 align-top hover:bg-slate-50 focus:bg-violet-50 focus:outline-none ${
                    f.corroborated === false ? 'opacity-70' : ''
                  }`}
                >
                  <td className="px-3 py-2.5"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-3 py-2.5 font-medium">
                    <div className="flex items-center gap-1.5">{f.attack_type} <SourceBadge source={f.source} /></div>
                    {f.corroborated === false && <div className="text-xs font-normal text-amber-700">Unconfirmed: review manually</div>}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs">{f.source_ip || '–'}</td>
                  <td className="px-3 py-2.5"><StatusBadge status={f.status} /></td>
                  <td className="px-3 py-2.5 font-mono text-xs text-slate-600">{lineList(f.evidence, 4)}</td>
                  <td className="max-w-xs px-3 py-2.5 text-slate-600"><span className="line-clamp-2">{f.reason}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}
