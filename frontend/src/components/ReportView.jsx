import Card from './Card.jsx'
import Correlations from './Correlations.jsx'
import SuspiciousIps from './SuspiciousIps.jsx'
import { downloadUrl } from '../services/api.js'
import { SEVERITY_BAR, formatSeconds } from '../services/format.js'

function Stat({ label, value }) {
  return (
    <div className="rounded-lg bg-slate-50 p-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums">{value}</div>
    </div>
  )
}

function Breakdown({ counts, colorFor }) {
  const max = Math.max(1, ...Object.values(counts))
  return (
    <ul className="space-y-2">
      {Object.entries(counts).map(([name, n]) => (
        <li key={name} className="grid grid-cols-[8.5rem_1fr_2rem] items-center gap-2 text-sm">
          <span className="truncate text-slate-700" title={name}>{name}</span>
          <span className="h-2.5 rounded-full bg-slate-100">
            <span className={`block h-full rounded-full ${colorFor(name)}`} style={{ width: `${(n / max) * 100}%` }} />
          </span>
          <span className="text-right tabular-nums">{n}</span>
        </li>
      ))}
    </ul>
  )
}

function Section({ title, children }) {
  return (
    <div className="border-t border-slate-100 pt-5">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      {children}
    </div>
  )
}

export default function ReportView({ report, jobId }) {
  const t = report.totals
  return (
    <Card
      title="4. Final report"
      action={
        <a href={downloadUrl(jobId)} download
          className="rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700">
          Download JSON
        </a>
      }
    >
      <div className="space-y-5">
        <p className="rounded-lg bg-violet-50 p-4 text-sm leading-relaxed text-slate-800">{report.executive_summary}</p>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <Stat label="Log entries" value={t.total_entries} />
          <Stat label="Sent to model" value={t.entries_sent_to_model} />
          <Stat label="Chunks OK / total" value={`${t.chunks_ok} / ${t.chunks_total}`} />
          <Stat label="Findings" value={t.total_findings} />
          <Stat label="Tokens (in + out)" value={`${t.prompt_tokens + t.output_tokens}`} />
          <Stat label="Model time" value={formatSeconds(t.model_seconds)} />
        </div>

        <div className="grid gap-6 border-t border-slate-100 pt-5 md:grid-cols-2">
          <div>
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">By severity</h3>
            <Breakdown counts={report.by_severity} colorFor={(s) => SEVERITY_BAR[s]} />
          </div>
          <div>
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">By attack type</h3>
            <Breakdown counts={report.by_attack_type} colorFor={() => 'bg-violet-500'} />
          </div>
        </div>

        <Section title="Cross-chunk correlations"><Correlations correlations={report.correlations} /></Section>
        <Section title="Suspicious IPs"><SuspiciousIps ips={report.suspicious_ips} /></Section>

        <Section title="Recommended actions">
          <ol className="list-decimal space-y-1.5 pl-5 text-sm text-slate-700">
            {report.recommended_actions.map((a) => <li key={a}>{a}</li>)}
          </ol>
        </Section>

        {(report.failed_chunks.length > 0 || report.duplicate_lines.length > 0) && (
          <Section title="Data quality">
            <ul className="space-y-1 text-sm text-slate-700">
              {report.failed_chunks.map((c) => (
                <li key={c.chunk_index} className="text-red-700">
                  Chunk {c.chunk_index} (lines {c.lines[0]}–{c.lines[1]}) failed: {c.error}
                </li>
              ))}
              {report.duplicate_lines.map((d) => (
                <li key={d.line}>Line {d.line} is an exact duplicate of line {d.duplicate_of} and was counted once.</li>
              ))}
            </ul>
          </Section>
        )}
      </div>
    </Card>
  )
}
