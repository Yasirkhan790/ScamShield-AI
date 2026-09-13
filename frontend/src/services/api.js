const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL
const API_BASE_URL = configuredBaseUrl ?? (import.meta.env.DEV ? 'http://localhost:8000' : '')

async function parseApiError(response, fallback) {
  const data = await response.json().catch(() => ({}))
  const detail = data?.detail
  if (Array.isArray(detail)) return detail?.[0]?.msg || fallback
  if (typeof detail === 'string') return detail
  return fallback
}

export async function getHealth() {
  const response = await fetch(`${API_BASE_URL}/api/health`)
  if (!response.ok) throw new Error('API health check failed.')
  return response.json()
}

export async function analyzeMessage(message) {
  const response = await fetch(`${API_BASE_URL}/api/analyze/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  })
  if (!response.ok) throw new Error(await parseApiError(response, 'Message analysis failed. Please try again.'))
  return response.json()
}

export async function analyzeUrl(url) {
  const response = await fetch(`${API_BASE_URL}/api/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  if (!response.ok) throw new Error(await parseApiError(response, 'URL analysis failed. Please check the address and try again.'))
  return response.json()
}

export async function analyzeScreenshot(file) {
  const formData = new FormData()
  formData.append('file', file)
  const response = await fetch(`${API_BASE_URL}/api/analyze/screenshot`, {
    method: 'POST',
    body: formData,
  })
  if (!response.ok) throw new Error(await parseApiError(response, 'Screenshot analysis failed. Please try a clearer image.'))
  return response.json()
}

export async function getHistory(limit = 20) {
  const response = await fetch(`${API_BASE_URL}/api/history?limit=${limit}`)
  if (!response.ok) throw new Error(await parseApiError(response, 'History could not be loaded.'))
  return response.json()
}

export async function getHistoryItem(id) {
  const response = await fetch(`${API_BASE_URL}/api/history/${id}`)
  if (!response.ok) throw new Error(await parseApiError(response, 'Analysis record could not be loaded.'))
  return response.json()
}
