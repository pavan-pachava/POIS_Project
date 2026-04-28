export function sanitizeHex(value) {
  const cleaned = (value || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
  if (!cleaned) return '00'
  return cleaned.length % 2 === 0 ? cleaned : `0${cleaned}`
}

export function short(value, max = 18) {
  if (!value) return ''
  if (value.length <= max) return value
  return `${value.slice(0, max)}...`
}
