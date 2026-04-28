import { useMemo, useState } from 'react'

function ProofPanel({ foundation, source, target, chain, reductionSteps }) {
  const [open, setOpen] = useState(false)

  const theoremSummary = useMemo(() => {
    const joined = (reductionSteps || [])
      .map((entry) => {
        if (typeof entry === 'string') return entry
        if (!entry?.step) return ''
        return entry.method ? `${entry.step} (${entry.method})` : entry.step
      })
      .filter(Boolean)
      .join(' | ')
    if (!joined) return 'No theorem selected.'
    return joined
  }, [reductionSteps])

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between rounded-lg bg-slate-100 px-3 py-2 text-left text-sm font-semibold text-slate-800"
      >
        <span>Reduction Proof Summary</span>
        <span>{open ? '▼' : '▶'}</span>
      </button>
      {open ? (
        <div className="mt-3 space-y-2 text-sm text-slate-700">
          <p>
            <strong>Chain:</strong> {(chain || [foundation, source, target]).join(' → ')}
          </p>
          <p>
            <strong>Theorem chain:</strong> {theoremSummary}
          </p>
          <p>
            <strong>Security claim (toy):</strong> if B is broken with advantage ε, then A can be broken with related
            advantage ε′ after the reduction overhead.
          </p>
        </div>
      ) : null}
    </section>
  )
}

export default ProofPanel
