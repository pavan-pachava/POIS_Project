function BuildPanel({ source, setSource, seed, setSeed, buildResult, loading, error }) {
  const primitives = ['OWF', 'PRG', 'PRF', 'ENC', 'CBC', 'CTR', 'OFB', 'MAC', 'CCA', 'HASH', 'DLPHASH', 'HMAC', 'RSA', 'DH', 'SIGN', 'MPC']
  const artifact = buildResult?.result?.artifact ?? buildResult?.artifact ?? '—'
  const sourceUpper = (source || '').toUpperCase()
  const primaryLabelByPrimitive = {
    PRG: 'Seed',
    PRF: 'Key',
    ENC: 'Key',
    MAC: 'Key',
    RSA: 'Key size (bits)',
    DH: 'Parameters',
  }
  const primaryHintByPrimitive = {
    PRG: 'e.g. a3f2',
    PRF: 'e.g. 1a2b3c4d',
    ENC: 'e.g. 1a2b3c4d',
    MAC: 'e.g. 1a2b3c4d',
    RSA: 'e.g. 32',
    DH: 'e.g. p,g,a,b',
  }
  const primaryLabel = primaryLabelByPrimitive[sourceUpper] || 'Key / Seed'
  const primaryHint = primaryHintByPrimitive[sourceUpper] || 'Enter value'

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-slate-900">Build Primitive (A)</h2>
      <label className="mt-4 block text-sm font-medium text-slate-700">
        Source primitive A
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
        >
          {primitives.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>

      <label className="mt-3 block text-sm font-medium text-slate-700">
        {primaryLabel}
        <input
          value={seed}
          onChange={(e) => setSeed(e.target.value)}
          placeholder={primaryHint}
          className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
        />
      </label>

      {error ? (
        <p className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
      ) : null}

      <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm">
        <span className="font-semibold text-slate-800">Artifact:</span>{' '}
        <span className="text-slate-700">{artifact}</span>
      </div>

      <div className="mt-4">
        <h3 className="text-sm font-semibold text-slate-800">Intermediate Steps</h3>
        {loading ? <p className="mt-2 text-sm text-slate-500">Loading build result…</p> : null}
        <ul className="mt-2 space-y-2">
          {(buildResult?.steps || []).map((step, index) => (
            <li key={index} className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
              <span className="mr-2 font-semibold text-slate-500">#{index + 1}</span>
              {step}
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

export default BuildPanel
