const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000/api'
const BASE_URL = (import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL).replace(/\/$/, '')

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    const parsed = await response.json()
    if (parsed && typeof parsed === 'object') {
      return parsed
    }
    return { data: parsed }
  }
  const text = await response.text()
  return text ? { detail: text } : {}
}

function extractErrorMessage(errorBody, status) {
  if (typeof errorBody === 'string' && errorBody.trim()) return errorBody
  if (errorBody?.detail && typeof errorBody.detail === 'string') return errorBody.detail
  if (errorBody?.message && typeof errorBody.message === 'string') return errorBody.message
  return `Request failed with status ${status}`
}

async function post(path, payload) {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  const parsed = await parseResponse(response)

  if (!response.ok) {
    throw new Error(extractErrorMessage(parsed, response.status))
  }

  return normalizeResponseShape(parsed)
}

function normalizeResponseShape(payload) {
  if (!payload || typeof payload !== 'object') return payload
  if (payload.result !== undefined && Array.isArray(payload.steps)) return payload
  if (payload.artifact !== undefined && Array.isArray(payload.steps)) {
    return { ...payload, result: { artifact: payload.artifact }, steps: payload.steps }
  }
  if (payload.output && typeof payload.output === 'object') {
    return {
      ...payload,
      result: payload.output.result ?? payload.output,
      steps: Array.isArray(payload.output.steps) ? payload.output.steps : []
    }
  }
  return payload
}

export async function runCryptoRequest(apiCall, payload, handlers = {}) {
  const { onLoadingChange, onError } = handlers
  onLoadingChange?.(true)
  onError?.('')
  try {
    return await apiCall(payload)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unexpected error'
    onError?.(message)
    throw error
  } finally {
    onLoadingChange?.(false)
  }
}

export function buildPrimitive(payload) {
  return post('/build', payload)
}

export function reducePrimitive(payload) {
  // PRD reduction rule: Column 2 must call only /api/reduce.
  // Direct target-primitive API calls would bypass Foundation -> A -> B reduction flow.
  return post('/reduce', payload)
}

export function callPrg(payload) {
  return post('/prg', payload)
}

export function callPrf(payload) {
  return post('/prf', payload)
}

export function callEncrypt(payload) {
  return post('/encrypt', payload)
}

export function callMac(payload) {
  return post('/mac', payload)
}

export function callHash(payload) {
  return post('/hash', payload)
}

export function callModes(payload) {
  return post('/modes', payload)
}

export function callCca(payload) {
  return post('/cca', payload)
}

export function callRsa(payload) {
  return post('/rsa', payload)
}

export function callDh(payload) {
  return post('/dh', payload)
}

export function callSign(payload) {
  return post('/sign', payload)
}

export function callMpc(payload) {
  return post('/mpc', payload)
}

export function callCpaAttack(payload) {
  return post('/cpa-attack', payload)
}

export function callIvReuseAttack(payload) {
  return post('/iv-reuse', payload)
}

export function callMalleabilityAttack(payload) {
  return post('/malleability', payload)
}
