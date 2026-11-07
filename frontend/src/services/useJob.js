import { useCallback, useEffect, useState } from 'react'
import { ACTIVE_STATES, FINISHED_STATES, getFindings, getReport, getStatus } from './api.js'

const POLL_MS = 2000

// Owns everything about one job: polls /status and /findings while it runs,
// loads the final report once it finishes.
export function useJob(jobId) {
  const [status, setStatus] = useState(null)
  const [findings, setFindings] = useState({ final: false, findings: [] })
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    if (!jobId) return
    try {
      const s = await getStatus(jobId)
      setStatus(s)
      setFindings(await getFindings(jobId))
      if (FINISHED_STATES.includes(s.state)) setReport(await getReport(jobId))
      setError('')
    } catch (e) {
      setError(e.message)
    }
  }, [jobId])

  // New job: clear old data and load once.
  useEffect(() => {
    setStatus(null)
    setReport(null)
    setFindings({ final: false, findings: [] })
    refresh()
  }, [refresh])

  // Poll only while the job is queued or running.
  const active = status && ACTIVE_STATES.includes(status.state)
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(refresh, POLL_MS)
    return () => clearInterval(timer)
  }, [active, refresh])

  return { status, findings, report, error, refresh }
}
