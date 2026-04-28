import { useEffect, useState } from 'react'
import AttackDemosPanel from './components/AttackDemosPanel'
import BuildPanel from './components/BuildPanel'
import FoundationToggle from './components/FoundationToggle'
import ProofPanel from './components/ProofPanel'
import ReducePanel from './components/ReducePanel'
import { buildPrimitive, reducePrimitive, runCryptoRequest } from './services/cryptoAPI'
import { sanitizeHex } from './utils/format'

const PRIMITIVE_OPTIONS = ['OWF', 'PRG', 'PRF', 'ENC', 'CBC', 'CTR', 'OFB', 'MAC', 'CCA', 'HASH', 'DLPHASH', 'HMAC', 'RSA', 'DH', 'SIGN', 'MPC']

function App() {
  const [foundation, setFoundation] = useState('AES')
  const [source, setSource] = useState('PRG')
  const [target, setTarget] = useState('PRF')
  const [seed, setSeed] = useState('a3f2')
  const [message, setMessage] = useState('1011')

  const [buildResult, setBuildResult] = useState(null)
  const [reduceResult, setReduceResult] = useState(null)
  const [loadingBuild, setLoadingBuild] = useState(false)
  const [loadingReduce, setLoadingReduce] = useState(false)
  const [buildError, setBuildError] = useState('')
  const [reduceError, setReduceError] = useState('')
  const buildArtifact = buildResult?.result?.artifact ?? buildResult?.artifact ?? ''

  useEffect(() => {
    let active = true

    runCryptoRequest(
      buildPrimitive,
      {
        foundation,
        source_primitive: source,
        seed: sanitizeHex(seed)
      },
      {
        onLoadingChange: (value) => {
          if (active) setLoadingBuild(value)
        },
        onError: (message) => {
          if (active) setBuildError(message)
        }
      }
    )
      .then((data) => {
        if (active) setBuildResult(data)
      })
      .catch(() => {
        if (active) setBuildResult(null)
      })

    return () => {
      active = false
    }
  }, [foundation, source, seed])

  useEffect(() => {
    let active = true
    const reduceSeed = buildArtifact || sanitizeHex(seed)
    const requestPayload = {
      foundation,
      source_primitive: source,
      target_primitive: target,
      seed: reduceSeed,
      message
    }

    // PRD rule: Column 2 must not call target primitive APIs directly.
    // Data flow is strictly Foundation -> A (Column 1 build) -> B (Column 2 reduce).
    // So Column 2 consumes only /api/reduce output, which internally derives B from A.
    runCryptoRequest(
      reducePrimitive,
      requestPayload,
      {
        onLoadingChange: (value) => {
          if (active) setLoadingReduce(value)
        },
        onError: (messageText) => {
          if (active) setReduceError(messageText)
        }
      }
    )
      .then((data) => {
        if (active) setReduceResult(data)
      })
      .catch(() => {
        if (active) setReduceResult(null)
      })

    return () => {
      active = false
    }
  }, [foundation, source, target, seed, message, buildArtifact])

  useEffect(() => {
    if (target === source) {
      const fallback = PRIMITIVE_OPTIONS.find((item) => item !== source) || 'PRF'
      setTarget(fallback)
    }
  }, [source, target])

  return (
    <main className="min-h-screen bg-slate-100 py-8">
      <div className="mx-auto w-full max-w-6xl px-4 sm:px-6">
        <h1 className="text-2xl font-bold text-slate-900 sm:text-3xl">Cryptographic Minicrypt Explorer</h1>
        <p className="mt-2 text-sm text-slate-600">Build and reduce primitives with live backend evaluation.</p>
      </div>

      <div className="mx-auto mt-6 w-full max-w-6xl px-4 sm:px-6">
      <FoundationToggle value={foundation} onChange={setFoundation} />
      </div>

      <div className="mx-auto mt-4 grid w-full max-w-6xl grid-cols-1 gap-4 px-4 sm:px-6 lg:grid-cols-2">
        <BuildPanel
          source={source}
          setSource={setSource}
          seed={seed}
          setSeed={setSeed}
          buildResult={buildResult}
          loading={loadingBuild}
          error={buildError}
        />
        <ReducePanel
          source={source}
          target={target}
          setTarget={setTarget}
          seed={seed}
          setSeed={setSeed}
          message={message}
          setMessage={setMessage}
          buildArtifact={buildArtifact}
          reduceResult={reduceResult}
          loading={loadingReduce}
          error={reduceError}
        />
      </div>

      <div className="mx-auto mt-4 w-full max-w-6xl px-4 pb-8 sm:px-6">
        <ProofPanel
          foundation={foundation}
          source={source}
          target={target}
          chain={reduceResult?.chain || [foundation, source, target]}
          reductionSteps={reduceResult?.reduction_steps || []}
        />
      </div>

      <AttackDemosPanel />
    </main>
  )
}

export default App
