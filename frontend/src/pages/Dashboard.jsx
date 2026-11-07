import { useState } from 'react'
import Header from '../components/Header.jsx'
import UploadPanel from '../components/UploadPanel.jsx'
import StatusPanel from '../components/StatusPanel.jsx'
import FindingsTable from '../components/FindingsTable.jsx'
import FindingDetail from '../components/FindingDetail.jsx'
import ReportView from '../components/ReportView.jsx'
import { ACTIVE_STATES, startAnalysis } from '../services/api.js'
import { recallJob, rememberJob } from '../services/format.js'
import { useJob } from '../services/useJob.js'

export default function Dashboard() {
  const [jobId, setJobId] = useState(recallJob)   // reopen the last job after a refresh
  const [selected, setSelected] = useState(null)
  const [actionError, setActionError] = useState('')
  const { status, findings, report, error, refresh } = useJob(jobId)
  const running = !!status && ACTIVE_STATES.includes(status.state)

  function onStarted(id) {
    rememberJob(id)
    setSelected(null)
    setJobId(id)
  }

  async function resume() {
    try {
      await startAnalysis(jobId)   // finished chunks are skipped by the backend
      setActionError('')
      refresh()
    } catch (e) {
      setActionError(e.message)
    }
  }

  return (
    <div className="min-h-screen">
      <Header />
      <main className="mx-auto grid max-w-7xl gap-5 px-4 py-6 sm:px-6 lg:grid-cols-[22rem_1fr]">
        <div className="space-y-5">
          <UploadPanel busy={running} onStarted={onStarted} />
          <StatusPanel status={status} error={actionError || error} onResume={resume} />
        </div>
        <div className="min-w-0 space-y-5">
          <FindingsTable findings={findings.findings} final={findings.final} running={running} onSelect={setSelected} />
          {report && <ReportView report={report} jobId={jobId} />}
        </div>
      </main>
      {selected && <FindingDetail finding={selected} jobId={jobId} onClose={() => setSelected(null)} />}
    </div>
  )
}
