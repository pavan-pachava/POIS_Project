function parseGgmTree(steps) {
  const safeSteps = Array.isArray(steps) ? steps.map((step) => String(step ?? '')) : []
  const intro = safeSteps.find((step) => step.toLowerCase().includes('ggm')) || ''
  const rootState =
    safeSteps.find((step) => step.includes('Initial state s0')) ||
    safeSteps.find((step) => step.includes('s0')) ||
    ''
  const levels = safeSteps
    .map((step) => {
      const match = step.match(/Bit\s+(\d+)='([01])'.*->\s*L=([^,\s;]+),\s*R=([^;\s]+);\s*choose\s*s\d+=([^;\s]+)/i)
      if (!match) return null

      return {
        level: Number(match[1]),
        bit: match[2],
        left: match[3],
        right: match[4],
        chosen: match[5]
      }
    })
    .filter(Boolean)
  const finalOutput = safeSteps.find((step) => step.toLowerCase().includes('output')) || ''

  return { intro, rootState, levels, finalOutput }
}

function ReducePanel({
  source,
  target,
  setTarget,
  seed: primaryInput,
  setSeed: setPrimaryInput,
  message,
  setMessage,
  buildArtifact,
  reduceResult,
  loading,
  error
}) {
  // PRD constraint: this panel is a pure reduction view (A -> B).
  // It must render only the backend /api/reduce response, because direct
  // target-primitive calls would bypass Column 1 artifact dependency.
  const primitives = ['OWF', 'PRG', 'PRF', 'ENC', 'CBC', 'CTR', 'OFB', 'MAC', 'CCA', 'HASH', 'DLPHASH', 'HMAC', 'RSA', 'DH', 'SIGN', 'MPC']
  const reductionSteps = (reduceResult?.reduction_steps || []).map((entry) => {
    if (typeof entry === 'string') return { step: entry, method: '' }
    if (entry && typeof entry === 'object') {
      return {
        step: typeof entry.step === 'string' ? entry.step : JSON.stringify(entry.step ?? entry),
        method: typeof entry.method === 'string' ? entry.method : ''
      }
    }
    return { step: String(entry ?? ''), method: '' }
  })
  const targetUpper = (target || '').toUpperCase()
  const needsKeyField = ['PRF', 'ENC', 'MAC'].includes(targetUpper)
  const needsSeedField = targetUpper === 'PRG'
  const needsDhParams = targetUpper === 'DH'
  const needsRsaFields = targetUpper === 'RSA'
  const primaryLabelByTarget = {
    PRG: 'Seed',
    PRF: 'Key',
    ENC: 'Key',
    MAC: 'Key',
    RSA: 'Key size (bits)',
    DH: 'Parameters'
  }
  const primaryHintByTarget = {
    PRG: 'e.g. a3f2',
    PRF: 'e.g. 1a2b3c4d',
    ENC: 'e.g. 1a2b3c4d',
    MAC: 'e.g. 1a2b3c4d',
    RSA: 'e.g. 32',
    DH: 'e.g. p,g,a,b'
  }
  const queryHintByTarget = {
    PRF: 'e.g. 1011',
    ENC: 'e.g. hello',
    MAC: 'e.g. audit-log-entry',
    MPC: 'e.g. 101011',
    DH: 'e.g. p,g,a,b',
    RSA: 'e.g. 42'
  }
  const activePrimaryLabel = primaryLabelByTarget[targetUpper] || 'Key / Seed'
  const activePrimaryHint = primaryHintByTarget[targetUpper] || 'Enter value'
  const messageLabel =
    targetUpper === 'PRF'
      ? 'Query'
      : targetUpper === 'ENC' || targetUpper === 'MAC'
        ? 'Message'
        : targetUpper === 'MPC'
          ? 'Input hint (used to derive bits)'
          : targetUpper === 'DH'
            ? 'Parameters'
            : targetUpper === 'RSA'
              ? 'Message'
              : 'Message / Query'
  const activeInputs = [
    activePrimaryLabel,
    messageLabel
  ]
  const artifactInFlow = buildArtifact || 'pending from Column 1 build'
  const outputSteps = reduceResult?.output?.steps || []
  const blockView = reduceResult?.output?.result?.blocks || []
  const finalResult = reduceResult?.output?.result ?? reduceResult?.result ?? {}
  // Prefer mode ciphertext fields before plain `output` (PRF subgraphs stash output in nested steps).
  const finalOutputValue =
    finalResult.output_hex ??
    finalResult.ciphertext ??
    finalResult.digest ??
    finalResult.tag ??
    finalResult.shared_secret ??
    finalResult.value ??
    finalResult.output
  const finalOutputLabelByTarget = {
    PRF: 'PRF output',
    PRG: 'PRG output',
    ENC: 'Ciphertext',
    CBC: 'Ciphertext',
    CTR: 'Ciphertext',
    OFB: 'Ciphertext',
    MAC: 'MAC tag',
    HASH: 'Hash output',
    DLPHASH: 'Hash output',
    HMAC: 'HMAC output',
    DH: 'Shared secret',
    RSA: 'RSA output',
    SIGN: 'Signature',
    MPC: 'MPC output'
  }
  const finalOutputLabel = finalOutputLabelByTarget[targetUpper] || 'Output'
  const resultStepTexts = Array.isArray(reduceResult?.output?.result?.steps)
    ? reduceResult.output.result.steps.map((step) => String(step ?? ''))
    : []
  const structuredTransitions = outputSteps
    .map((step, index) => {
      if (!step || typeof step !== 'object') return null
      const nestedSteps = Array.isArray(step.output?.steps)
        ? step.output.steps.map((item) => String(item ?? '')).filter(Boolean)
        : []

      if (nestedSteps.length === 0) return null

      return {
        id: `${step.from || 'step'}-${step.to || 'output'}-${index}`,
        from: String(step.from || source),
        to: String(step.to || target),
        steps: nestedSteps
      }
    })
    .filter(Boolean)

  const flatOutputStepTexts = outputSteps
    .filter((step) => typeof step === 'string')
    .map((step) => String(step ?? ''))

  const allStepTexts = [
    ...flatOutputStepTexts,
    ...structuredTransitions.flatMap((transition) => transition.steps),
    ...resultStepTexts
  ]

  const ggmTreeSteps = allStepTexts.filter((step) => step.includes('Bit '))
  const chainSteps = allStepTexts.filter((step) => step.includes('Block '))
  const ggmCards =
    structuredTransitions.length > 0
      ? structuredTransitions
      : ggmTreeSteps.length > 0
        ? [
            {
              id: 'ggm-fallback',
              from: source,
              to: target,
              steps: ggmTreeSteps
            }
          ]
        : []
  const ggmTrees = ggmCards.map((card) => ({
    ...card,
    tree: parseGgmTree(card.steps)
  }))

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-slate-900">Reduce A → B</h2>
      <p className="mt-2 text-sm text-slate-600">
        Source A: <strong className="text-slate-800">{source}</strong>
      </p>

      <label className="mt-4 block text-sm font-medium text-slate-700">
        Target primitive B
        <select
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
        >
          {primitives.filter((item) => item !== source).map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>

      {needsSeedField ? (
        <label className="mt-3 block text-sm font-medium text-slate-700">
          {activePrimaryLabel}
          <input
            value={primaryInput}
            onChange={(e) => setPrimaryInput(e.target.value)}
            placeholder={activePrimaryHint}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
          />
        </label>
      ) : null}

      {needsKeyField ? (
        <label className="mt-3 block text-sm font-medium text-slate-700">
          {activePrimaryLabel}
          <input
            value={primaryInput}
            onChange={(e) => setPrimaryInput(e.target.value)}
            placeholder={activePrimaryHint}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
          />
        </label>
      ) : null}

      {needsRsaFields ? (
        <label className="mt-3 block text-sm font-medium text-slate-700">
          {activePrimaryLabel}
          <input
            value={primaryInput}
            onChange={(e) => setPrimaryInput(e.target.value)}
            placeholder={activePrimaryHint}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
          />
        </label>
      ) : null}

      <label className="mt-3 block text-sm font-medium text-slate-700">
        {needsDhParams ? 'Parameters' : messageLabel}
        <input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder={needsDhParams ? 'e.g. p,g,a,b' : queryHintByTarget[targetUpper]}
          className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
        />
      </label>

      <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3">
        <h3 className="text-sm font-semibold text-amber-900">Data Flow: Column 1 {'->'} Column 2</h3>
        <p className="mt-1 text-xs text-amber-800">Using artifact from Column 1 build:</p>
        <p className="mt-1 break-all rounded-md border border-amber-200 bg-white px-2 py-1 font-mono text-xs text-slate-800">{artifactInFlow}</p>
      </div>

      <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
        <h3 className="text-sm font-semibold text-slate-800">Dynamic Inputs</h3>
        <p className="mt-1 text-xs text-slate-600">Target primitive: <span className="font-semibold text-slate-800">{targetUpper}</span></p>
        <div className="mt-2 flex flex-wrap gap-2">
          {activeInputs.map((inputName) => (
            <span key={inputName} className="rounded-full border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-medium text-blue-800">
              {inputName}
            </span>
          ))}
        </div>
      </div>

      {error ? (
        <p className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
      ) : null}

      <div className="mt-4">
        <h3 className="text-sm font-semibold text-slate-800">Reduction Steps</h3>
        {loading ? <p className="mt-2 text-sm text-slate-500">Loading reduction result…</p> : null}
        <ul className="mt-2 space-y-2">
          {reductionSteps.map((entry, index) => (
            <li key={index} className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
              <span className="mr-2 font-semibold text-slate-500">#{index + 1}</span>
              {entry.step}
              {entry.method ? <span className="ml-2 text-slate-500">({entry.method})</span> : null}
            </li>
          ))}
        </ul>
      </div>

      {ggmTrees.length > 0 ? (
        <div className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 p-3">
          <h3 className="text-sm font-semibold text-slate-800">GGM Tree View</h3>
          <div className="mt-2 space-y-2">
            {ggmTrees.map((card) => (
              <div key={card.id} className="rounded-md border border-slate-200 bg-white p-2">
                  <p className="text-xs font-semibold text-slate-700">
                    {card.from} {'->'} {card.to}
                  </p>

                {card.tree.intro ? <p className="mt-1 text-[11px] text-slate-600">{card.tree.intro}</p> : null}

                {card.tree.rootState ? (
                  <div className="mt-2 rounded-md border border-slate-200 bg-slate-50 px-2 py-1">
                    <p className="text-[11px] font-medium text-slate-700">Root (s0)</p>
                    <p className="mt-1 break-all font-mono text-[11px] text-slate-700">{card.tree.rootState}</p>
                  </div>
                ) : null}

                {card.tree.levels.length > 0 ? (
                  <div className="mt-2 space-y-2">
                    {card.tree.levels.map((node) => (
                      <div key={`${card.id}-level-${node.level}`} className="rounded-md border border-slate-200 bg-slate-50 p-2">
                        <p className="text-[11px] font-semibold text-slate-700">
                          Level {node.level} | bit = {node.bit}
                        </p>
                        <div className="mt-1 grid grid-cols-1 gap-2 sm:grid-cols-2">
                          <div
                            className={`rounded-md border px-2 py-1 ${
                              node.bit === '0' ? 'border-emerald-300 bg-emerald-50' : 'border-slate-200 bg-white'
                            }`}
                          >
                            <p className="text-[10px] font-semibold text-slate-600">0 / Left</p>
                            <p className="mt-1 break-all font-mono text-[11px] text-slate-700">{node.left}</p>
                          </div>
                          <div
                            className={`rounded-md border px-2 py-1 ${
                              node.bit === '1' ? 'border-emerald-300 bg-emerald-50' : 'border-slate-200 bg-white'
                            }`}
                          >
                            <p className="text-[10px] font-semibold text-slate-600">1 / Right</p>
                            <p className="mt-1 break-all font-mono text-[11px] text-slate-700">{node.right}</p>
                          </div>
                        </div>
                        <p className="mt-1 text-[11px] text-slate-700">Chosen child: {node.chosen}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <ol className="mt-2 list-decimal space-y-1 pl-4 text-xs text-slate-700">
                    {card.steps.map((step, index) => (
                      <li key={`${card.id}-${index}`}>{step}</li>
                    ))}
                  </ol>
                )}

                {card.tree.finalOutput ? (
                  <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] text-slate-700">
                    {card.tree.finalOutput}
                  </p>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {blockView.length > 0 ? (
        <div className="mt-4 rounded-lg border border-indigo-200 bg-indigo-50 p-3">
          <h3 className="text-sm font-semibold text-slate-800">Block View (Modes)</h3>
          <ul className="mt-2 space-y-1 text-xs text-slate-700">
            {blockView.map((block, index) => (
              <li key={index}>
                #{index + 1} in={block.input || '-'} ks={block.keystream || '-'} out={block.output || block}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {chainSteps.length > 0 ? (
        <div className="mt-4 rounded-lg border border-cyan-200 bg-cyan-50 p-3">
          <h3 className="text-sm font-semibold text-slate-800">Merkle-Damgård Chain View</h3>
          <ul className="mt-2 space-y-1 text-xs text-slate-700">
            {chainSteps.map((step, index) => (
              <li key={index}>→ {step}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="mt-4 rounded-lg border border-violet-200 bg-violet-50 p-3">
        <h3 className="text-sm font-semibold text-slate-800">Final Output</h3>
        <div className="mt-2 rounded-lg border border-violet-200 bg-white p-3">
          <p className="text-xs font-semibold text-slate-600">{finalOutputLabel}</p>
          <p className="mt-1 break-all font-mono text-sm text-slate-900">{finalOutputValue ?? 'Not available yet'}</p>
        </div>
        <details className="mt-3">
          <summary className="cursor-pointer text-xs font-medium text-slate-700">Show raw output JSON</summary>
          <pre className="mt-2 whitespace-pre-wrap break-words rounded-lg bg-white p-3 text-xs text-slate-700">
{JSON.stringify(reduceResult?.output || {}, null, 2)}
          </pre>
        </details>
      </div>
    </section>
  )
}

export default ReducePanel
