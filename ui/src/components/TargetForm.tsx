import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'

// Custom headers are edited as plain "Header-Name: value" lines (one per
// line) rather than a raw JSON textarea or a dynamic row-editor -- fastest
// to build, and it's the format pentesters already read/write in curl,
// Burp, etc.
function parseHeadersText(text: string): Record<string, string> {
  const headers: Record<string, string> = {}
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const idx = line.indexOf(':')
    if (idx === -1) continue
    const name = line.slice(0, idx).trim()
    const value = line.slice(idx + 1).trim()
    if (name) headers[name] = value
  }
  return headers
}

function formatHeadersText(headers: Record<string, string> | null | undefined): string {
  if (!headers) return ''
  return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
}

// Full, internally-consistent header sets for common real browsers -- not
// just a User-Agent swap. Mixing a Chrome UA with no sec-ch-ua/Sec-Fetch-*
// headers (or the wrong Accept-Language format) is itself a fingerprinting
// signal, so each entry is a complete, coherent set from one real browser.
const HEADER_PROFILES: { label: string; headers: Record<string, string> }[] = [
  {
    label: 'Chrome / Windows',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
    },
  },
  {
    label: 'Firefox / Windows',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
    },
  },
  {
    label: 'Safari / macOS',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
  },
  {
    label: 'Edge / Windows',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'sec-ch-ua': '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
    },
  },
  {
    label: 'Chrome / Android',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      'sec-ch-ua-mobile': '?1',
      'sec-ch-ua-platform': '"Android"',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-User': '?1',
      'Upgrade-Insecure-Requests': '1',
    },
  },
]

function randomHeaderProfile() {
  return HEADER_PROFILES[Math.floor(Math.random() * HEADER_PROFILES.length)]
}

export default function TargetForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = !!id

  const [formData, setFormData] = useState({ name: '', url: '', notes: '' })
  const [customHeadersText, setCustomHeadersText] = useState('')
  const [lastProfile, setLastProfile] = useState<string | null>(null)

  const handleRandomizeHeaders = () => {
    const profile = randomHeaderProfile()
    setCustomHeadersText(formatHeadersText(profile.headers))
    setLastProfile(profile.label)
  }

  // Load existing target for edit mode
  const { data: existingTarget } = useQuery({
    queryKey: ['target', id],
    queryFn: async () => {
      if (!isEdit) return null
      const res = await fetch(`/api/targets/${id}`)
      return res.json()
    },
    enabled: isEdit,
  })

  useEffect(() => {
    if (existingTarget) {
      setFormData({
        name: existingTarget.name,
        url: existingTarget.url,
        notes: existingTarget.notes || '',
      })
      setCustomHeadersText(formatHeadersText(existingTarget.custom_headers))
    }
  }, [existingTarget])

  const mutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const url = isEdit ? `/api/targets/${id}` : '/api/targets'
      const method = isEdit ? 'PUT' : 'POST'
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...data,
          custom_headers: parseHeadersText(customHeadersText),
        }),
      })
      if (!res.ok) throw new Error('Failed to save target')
      return res.json()
    },
    onSuccess: () => {
      navigate('/targets')
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    mutation.mutate(formData)
  }

  return (
    <div className="max-w-2xl">
      <h2 className="text-2xl font-bold mb-6">{isEdit ? 'Edit Target' : 'New Target'}</h2>

      <form onSubmit={handleSubmit} className="card space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="input-field"
            placeholder="e.g., Lab Environment"
            required
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">URL or IP</label>
          <input
            type="text"
            value={formData.url}
            onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            className="input-field"
            placeholder="e.g., lab.local or 192.168.1.1"
            required
          />
        </div>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Notes</label>
          <textarea
            value={formData.notes}
            onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
            className="input-field"
            rows={3}
            placeholder="Optional notes about this target..."
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="block text-sm text-gray-400">
              Custom Headers <span className="text-gray-500">(one per line, sent with every request to this target)</span>
            </label>
            <button
              type="button"
              onClick={handleRandomizeHeaders}
              className="text-xs px-2 py-1 rounded border border-gray-600 hover:bg-gray-700 whitespace-nowrap"
              title="Fill in a complete, realistic browser header set (User-Agent + matching Accept/Sec-Fetch/sec-ch-ua headers) to blend in as normal browser traffic. Edit freely after generating."
            >
              🎲 Randomize
            </button>
          </div>
          <textarea
            value={customHeadersText}
            onChange={(e) => { setCustomHeadersText(e.target.value); setLastProfile(null) }}
            className="input-field font-mono text-sm"
            rows={6}
            placeholder={'Authorization: Bearer <token>\nCookie: session=...\nX-Api-Key: ...'}
            spellCheck={false}
          />
          {lastProfile && (
            <p className="text-xs text-gray-500 mt-1">
              Generated a full "{lastProfile}" header set. Edit any line above, or randomize again.
            </p>
          )}
        </div>

        <div className="flex gap-3 pt-4">
          <button type="submit" className="btn-primary" disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving...' : isEdit ? 'Update Target' : 'Create Target'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/targets')}
            className="btn-secondary"
          >
            Cancel
          </button>
        </div>

        {mutation.isError && (
          <div className="text-red-400 text-sm">
            Failed to save target. Please try again.
          </div>
        )}
      </form>
    </div>
  )
}
