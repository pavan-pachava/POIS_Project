import { useState } from 'react'
import { callCpaAttack, callHash, callIvReuseAttack, callMalleabilityAttack, callMpc, runCryptoRequest } from '../services/cryptoAPI'
import { sanitizeHex } from '../utils/format'

function AttackCard({ title, description, onRun, buttonLabel = 'Run Demo', children, result, loading, error, details = null }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h3 className="text-base font-semibold text-slate-900">{title}</h3>
      <p className="mt-1 text-sm text-slate-600">{description}</p>

      <div className="mt-3 space-y-3">{children}</div>

      <button
        onClick={onRun}
        className="mt-3 rounded-lg bg-blue-600 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-700"
      >
        {buttonLabel}
      </button>

      {loading ? <p className="mt-2 text-sm text-slate-500">Running demo…</p> : null}
      {error ? <p className="mt-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p> : null}
      {details}

      <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
        <h4 className="text-sm font-semibold text-slate-800">Result</h4>
        <pre className="mt-2 whitespace-pre-wrap break-words rounded-lg bg-white p-3 text-xs text-slate-700">
{JSON.stringify(result?.result || {}, null, 2)}
        </pre>
      </div>
      <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
        <h4 className="text-sm font-semibold text-slate-800">Explanation Steps</h4>
        <ul className="mt-2 space-y-1 text-xs text-slate-700">
          {(result?.steps || []).map((step, index) => (
            <li key={index}>#{index + 1} {step}</li>
          ))}
        </ul>
      </div>
    </section>
  )
}

function AttackDemosPanel() {
  const [cpaPayload, setCpaPayload] = useState({
    key: '1a2b3c4d',
    m0: 'left-message',
    m1: 'right-message',
    nonce: 7,
    trials: 10
  })
  const [ivPayload, setIvPayload] = useState({
    key: '1a2b3c4d',
    known_plaintext: 'known-prefix-plaintext',
    target_plaintext: 'target-prefix-secret',
    nonce: 7
  })
  const [malleabilityPayload, setMalleabilityPayload] = useState({
    key: '1a2b3c4d',
    plaintext: 'pay=100',
    flip_mask_hex: '01',
    nonce: 9
  })
  const [birthdayPayload, setBirthdayPayload] = useState({ bits: 12 })
  const [mpcPayload, setMpcPayload] = useState({
    operation: 'millionaire',
    m0: 10,
    m1: 20,
    choice_bit: 1,
    x_value: 9,
    y_value: 6,
    bit_width: 8
  })

  const [cpaResult, setCpaResult] = useState(null)
  const [ivResult, setIvResult] = useState(null)
  const [malleabilityResult, setMalleabilityResult] = useState(null)
  const [birthdayResult, setBirthdayResult] = useState(null)
  const [mpcResult, setMpcResult] = useState(null)

  const [cpaLoading, setCpaLoading] = useState(false)
  const [ivLoading, setIvLoading] = useState(false)
  const [malleabilityLoading, setMalleabilityLoading] = useState(false)
  const [birthdayLoading, setBirthdayLoading] = useState(false)
  const [mpcLoading, setMpcLoading] = useState(false)

  const [cpaError, setCpaError] = useState('')
  const [ivError, setIvError] = useState('')
  const [malleabilityError, setMalleabilityError] = useState('')
  const [birthdayError, setBirthdayError] = useState('')
  const [mpcError, setMpcError] = useState('')

  const runCpaDemo = () =>
    runCryptoRequest(
      callCpaAttack,
      { ...cpaPayload, key: sanitizeHex(cpaPayload.key) },
      {
        onLoadingChange: setCpaLoading,
        onError: setCpaError
      }
    )
      .then(setCpaResult)
      .catch(() => setCpaResult(null))

  const runIvDemo = () =>
    runCryptoRequest(
      callIvReuseAttack,
      { ...ivPayload, key: sanitizeHex(ivPayload.key) },
      {
        onLoadingChange: setIvLoading,
        onError: setIvError
      }
    )
      .then(setIvResult)
      .catch(() => setIvResult(null))

  const runMalleabilityDemo = () =>
    runCryptoRequest(
      callMalleabilityAttack,
      {
        ...malleabilityPayload,
        key: sanitizeHex(malleabilityPayload.key),
        flip_mask_hex: sanitizeHex(malleabilityPayload.flip_mask_hex)
      },
      {
        onLoadingChange: setMalleabilityLoading,
        onError: setMalleabilityError
      }
    )
      .then(setMalleabilityResult)
      .catch(() => setMalleabilityResult(null))

  const runBirthdayDemo = () =>
    runCryptoRequest(
      callHash,
      {
        scheme: 'birthday',
        bits: birthdayPayload.bits,
        truncate_bits: birthdayPayload.bits,
        message: ''
      },
      {
        onLoadingChange: setBirthdayLoading,
        onError: setBirthdayError
      }
    )
      .then(setBirthdayResult)
      .catch(() => setBirthdayResult(null))

  const runMpcDemo = () =>
    runCryptoRequest(
      callMpc,
      {
        operation: mpcPayload.operation,
        m0: Number(mpcPayload.m0) || 0,
        m1: Number(mpcPayload.m1) || 0,
        choice_bit: Number(mpcPayload.choice_bit) ? 1 : 0,
        a_bit: Number(mpcPayload.x_value) ? 1 : 0,
        b_bit: Number(mpcPayload.y_value) ? 1 : 0,
        x_value: Number(mpcPayload.x_value) || 0,
        y_value: Number(mpcPayload.y_value) || 0,
        bit_width: Number(mpcPayload.bit_width) || 8
      },
      {
        onLoadingChange: setMpcLoading,
        onError: setMpcError
      }
    )
      .then(setMpcResult)
      .catch(() => setMpcResult(null))

  const birthdayData = birthdayResult?.result || {}

  return (
    <section className="mx-auto mt-4 w-full max-w-6xl px-4 pb-8 sm:px-6">
      <h2 className="text-lg font-semibold text-slate-900">Attack Demonstrations</h2>
      <div className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <AttackCard
          title="CPA Attack Demo (IND-CPA)"
          description="Challenge ciphertext is distinguishable when nonce reuse makes encryption deterministic."
          onRun={runCpaDemo}
          result={cpaResult}
          loading={cpaLoading}
          error={cpaError}
        >
          <label className="block text-sm text-slate-700">
            Key (hex)
            <input value={cpaPayload.key} onChange={(e) => setCpaPayload({ ...cpaPayload, key: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Message m0
            <input value={cpaPayload.m0} onChange={(e) => setCpaPayload({ ...cpaPayload, m0: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Message m1
            <input value={cpaPayload.m1} onChange={(e) => setCpaPayload({ ...cpaPayload, m1: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Reused nonce
            <input type="number" value={cpaPayload.nonce} onChange={(e) => setCpaPayload({ ...cpaPayload, nonce: Number(e.target.value) || 0 })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Trials
            <input type="number" value={cpaPayload.trials} onChange={(e) => setCpaPayload({ ...cpaPayload, trials: Number(e.target.value) || 1 })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
        </AttackCard>

        <AttackCard
          title="IV/Nonce Reuse Attack"
          description="Reusing nonce leaks xor relation and enables target plaintext recovery from known plaintext."
          onRun={runIvDemo}
          result={ivResult}
          loading={ivLoading}
          error={ivError}
        >
          <label className="block text-sm text-slate-700">
            Key (hex)
            <input value={ivPayload.key} onChange={(e) => setIvPayload({ ...ivPayload, key: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Known plaintext
            <input value={ivPayload.known_plaintext} onChange={(e) => setIvPayload({ ...ivPayload, known_plaintext: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Target plaintext
            <input value={ivPayload.target_plaintext} onChange={(e) => setIvPayload({ ...ivPayload, target_plaintext: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Reused nonce
            <input type="number" value={ivPayload.nonce} onChange={(e) => setIvPayload({ ...ivPayload, nonce: Number(e.target.value) || 0 })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
        </AttackCard>

        <AttackCard
          title="Malleability Attack"
          description="Bit flips in ciphertext produce predictable flips in decrypted plaintext."
          onRun={runMalleabilityDemo}
          result={malleabilityResult}
          loading={malleabilityLoading}
          error={malleabilityError}
        >
          <label className="block text-sm text-slate-700">
            Key (hex)
            <input value={malleabilityPayload.key} onChange={(e) => setMalleabilityPayload({ ...malleabilityPayload, key: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Plaintext
            <input value={malleabilityPayload.plaintext} onChange={(e) => setMalleabilityPayload({ ...malleabilityPayload, plaintext: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Flip mask (hex)
            <input value={malleabilityPayload.flip_mask_hex} onChange={(e) => setMalleabilityPayload({ ...malleabilityPayload, flip_mask_hex: e.target.value })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm text-slate-700">
            Nonce
            <input type="number" value={malleabilityPayload.nonce} onChange={(e) => setMalleabilityPayload({ ...malleabilityPayload, nonce: Number(e.target.value) || 0 })} className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" />
          </label>
        </AttackCard>

        <AttackCard
          title="Birthday Attack"
          description="Find collisions on truncated hash outputs. Expected complexity O(2^(n/2))."
          onRun={runBirthdayDemo}
          buttonLabel="Run Attack"
          result={birthdayResult}
          loading={birthdayLoading}
          error={birthdayError}
          details={
            <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
              <p><span className="font-semibold text-slate-800">Expected complexity:</span> O(2^(n/2))</p>
              <p className="mt-1"><span className="font-semibold text-slate-800">Attempts:</span> {birthdayData.attempts ?? '-'}</p>
              <p className="mt-1"><span className="font-semibold text-slate-800">Colliding inputs:</span> {birthdayData.colliding_input_1 && birthdayData.colliding_input_2 ? `${birthdayData.colliding_input_1}, ${birthdayData.colliding_input_2}` : '-'}</p>
              <p className="mt-1"><span className="font-semibold text-slate-800">Truncated hash:</span> {birthdayData.truncated_hash ?? '-'}</p>
            </div>
          }
        >
          <label className="block text-sm text-slate-700">
            Bit size (n)
            <input
              type="number"
              min={8}
              max={16}
              step={2}
              value={birthdayPayload.bits}
              onChange={(e) => setBirthdayPayload({ bits: Number(e.target.value) || 8 })}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </label>
        </AttackCard>

        <AttackCard
          title="PA18-PA20 MPC Demos"
          description="Run Bellare-Micali OT and secure circuit evaluation (Millionaire, Equality, Addition)."
          onRun={runMpcDemo}
          buttonLabel="Run MPC"
          result={mpcResult}
          loading={mpcLoading}
          error={mpcError}
        >
          <label className="block text-sm text-slate-700">
            Operation
            <select
              value={mpcPayload.operation}
              onChange={(e) => setMpcPayload({ ...mpcPayload, operation: e.target.value })}
              className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            >
              <option value="ot">OT (1-out-of-2)</option>
              <option value="millionaire">Millionaire (x &gt; y)</option>
              <option value="equality">Equality (x == y)</option>
              <option value="addition">Addition (x + y mod 2^n)</option>
              <option value="and">Secure AND</option>
              <option value="xor">Secure XOR</option>
              <option value="not">Secure NOT</option>
              <option value="2pc">2PC AND (compat)</option>
            </select>
          </label>

          {mpcPayload.operation === 'ot' ? (
            <>
              <label className="block text-sm text-slate-700">
                m0
                <input
                  type="number"
                  value={mpcPayload.m0}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, m0: Number(e.target.value) || 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block text-sm text-slate-700">
                m1
                <input
                  type="number"
                  value={mpcPayload.m1}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, m1: Number(e.target.value) || 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block text-sm text-slate-700">
                Choice bit b
                <input
                  type="number"
                  min={0}
                  max={1}
                  value={mpcPayload.choice_bit}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, choice_bit: Number(e.target.value) ? 1 : 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
            </>
          ) : null}

          {['millionaire', 'equality', 'addition'].includes(mpcPayload.operation) ? (
            <>
              <label className="block text-sm text-slate-700">
                x
                <input
                  type="number"
                  value={mpcPayload.x_value}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, x_value: Number(e.target.value) || 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block text-sm text-slate-700">
                y
                <input
                  type="number"
                  value={mpcPayload.y_value}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, y_value: Number(e.target.value) || 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block text-sm text-slate-700">
                Bit width n
                <input
                  type="number"
                  min={1}
                  max={32}
                  value={mpcPayload.bit_width}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, bit_width: Number(e.target.value) || 8 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
            </>
          ) : null}

          {['and', 'xor', '2pc', 'not'].includes(mpcPayload.operation) ? (
            <>
              <label className="block text-sm text-slate-700">
                a bit
                <input
                  type="number"
                  min={0}
                  max={1}
                  value={mpcPayload.x_value}
                  onChange={(e) => setMpcPayload({ ...mpcPayload, x_value: Number(e.target.value) ? 1 : 0 })}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              {mpcPayload.operation !== 'not' ? (
                <label className="block text-sm text-slate-700">
                  b bit
                  <input
                    type="number"
                    min={0}
                    max={1}
                    value={mpcPayload.y_value}
                    onChange={(e) => setMpcPayload({ ...mpcPayload, y_value: Number(e.target.value) ? 1 : 0 })}
                    className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                  />
                </label>
              ) : null}
            </>
          ) : null}
        </AttackCard>
      </div>
    </section>
  )
}

export default AttackDemosPanel
