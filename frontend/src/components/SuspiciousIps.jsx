import { SeverityBadge } from './Badges.jsx'

export default function SuspiciousIps({ ips }) {
  if (!ips.length) return <p className="text-sm text-slate-500">No suspicious IPs.</p>
  return (
    <div className="-mx-4 overflow-x-auto sm:mx-0">
      <table className="w-full min-w-[560px] text-left text-sm">
        <thead className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-3 py-2 font-medium">IP</th>
            <th className="px-3 py-2 font-medium">Max severity</th>
            <th className="px-3 py-2 font-medium">Attacks</th>
            <th className="px-3 py-2 font-medium">Requests</th>
            <th className="px-3 py-2 font-medium">Signals (rule-based counts)</th>
          </tr>
        </thead>
        <tbody>
          {ips.map((ip) => (
            <tr key={ip.ip} className="border-b border-slate-100 align-top">
              <td className="px-3 py-2 font-mono text-xs">
                {ip.ip}
                {ip.users.length > 0 && <div className="font-sans text-slate-500">user: {ip.users.join(', ')}</div>}
              </td>
              <td className="px-3 py-2"><SeverityBadge severity={ip.max_severity} /></td>
              <td className="px-3 py-2">{ip.attack_types.join(', ')}</td>
              <td className="px-3 py-2 tabular-nums">{ip.requests}</td>
              <td className="px-3 py-2 text-xs text-slate-600">
                {Object.entries(ip.signals).map(([k, v]) => `${k} ${v}`).join(' · ') || '–'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
