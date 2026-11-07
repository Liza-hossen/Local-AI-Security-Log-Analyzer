import { useState } from 'react'
import Card from './Card.jsx'
import { startAnalysis, uploadLog } from '../services/api.js'

const ALLOWED = ['.log', '.txt']

// Checks the backend also does; repeated here for instant feedback.
function validate(file) {
  if (!file) return 'Choose a log file first.'
  if (!ALLOWED.some((ext) => file.name.toLowerCase().endsWith(ext))) {
    return `"${file.name}" is not supported. Only .log and .txt files are accepted.`
  }
  if (file.size === 0) return 'The file is empty.'
  return ''
}

export default function UploadPanel({ busy, onStarted }) {
  const [file, setFile] = useState(null)
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)
  const [dragging, setDragging] = useState(false)

  function pick(f) {
    setFile(f || null)
    setError(f ? validate(f) : '')
  }

  async function start() {
    const problem = validate(file)
    if (problem) return setError(problem)
    setWorking(true)
    setError('')
    try {
      const { job_id: jobId } = await uploadLog(file)
      await startAnalysis(jobId)
      onStarted(jobId)
      setFile(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setWorking(false)
    }
  }

  return (
    <Card title="1. Upload a log">
      <label
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files[0]) }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-4 py-8 text-center transition ${
          dragging ? 'border-violet-400 bg-violet-50' : 'border-slate-300 hover:border-slate-400'
        }`}
      >
        <input type="file" accept=".log,.txt" className="sr-only" onChange={(e) => pick(e.target.files[0])} />
        <span className="text-sm font-medium">{file ? file.name : 'Drop a .log or .txt file, or click to choose'}</span>
        <span className="mt-1 text-xs text-slate-500">
          {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Max 50 MB. The file never leaves this machine.'}
        </span>
      </label>
      {error && <p role="alert" className="mt-3 rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
      <button
        type="button"
        onClick={start}
        disabled={!file || !!error || working || busy}
        className="mt-4 w-full rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-violet-700 disabled:cursor-not-allowed disabled:bg-slate-300"
      >
        {working ? 'Uploading…' : busy ? 'Another analysis is running' : 'Start Analysis'}
      </button>
    </Card>
  )
}
