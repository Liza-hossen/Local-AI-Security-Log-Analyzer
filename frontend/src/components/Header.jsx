export default function Header() {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto max-w-7xl px-4 py-5 sm:px-6">
        <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">Local AI Security Log Analyzer</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-600">
          Finds brute force, SQL injection, scanning, request floods and unauthorized access in server logs.
          Runs fully offline: a local Qwen model through Ollama, inside 4 GB of RAM and 2,048 tokens per call,
          with code-level checks on every answer.
        </p>
      </div>
    </header>
  )
}
