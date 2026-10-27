import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Play, Square, FileText, Plus, Trash2 } from 'lucide-react'

export default function ScansList() {
  const queryClient = useQueryClient()
  const [selectedTargetId, setSelectedTargetId] = useState<string>('')
  const [evasionEnabled, setEvasionEnabled] = useState(true)
  const [requestDelay, setRequestDelay] = useState<string>('')
  const [externalLookups, setExternalLookups] = useState(true)

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans')
      if (!res.ok) throw new Error('Failed to load scans')
      return res.json()
    },
    refetchInterval: 3000,
  })

  // Needed to populate the "start a new scan" target picker below -- there
  // was previously no UI anywhere that could create a scan in the first
  // place, only start/stop ones that already existed.
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch('/api/targets')
      if (!res.ok) throw new Error('Failed to load targets')
      return res.json()
    },
  })

  const targetById = (id: number) => targets?.find((t: any) => t.id === id)

  const newScanMutation = useMutation({
    mutationFn: async (targetId: number) => {
      const createRes = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: targetId,
          evasion_enabled: evasionEnabled,
          request_delay: requestDelay.trim() === '' ? null : parseFloat(requestDelay),
          enable_external_lookups: externalLookups,
        }),
      })
      if (!createRes.ok) throw new Error('Failed to create scan')
      const scan = await createRes.json()

      const startRes = await fetch(`/api/scans/${scan.id}/start`, { method: 'POST' })
      if (!startRes.ok) throw new Error('Scan was created but failed to start')
      return startRes.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setSelectedTargetId('')
    },
  })

  const startMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await fetch(`/api/scans/${id}/start`, { method: 'POST' })
      if (!res.ok) throw new Error('Failed to start scan')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const stopMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await fetch(`/api/scans/${id}/stop`, { method: 'POST' })
      if (!res.ok) throw new Error('Failed to stop scan')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await fetch(`/api/scans/${id}`, { method: 'DELETE' })
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        throw new Error(body?.detail || 'Failed to delete scan')
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['target-history'] })
      queryClient.invalidateQueries({ queryKey: ['target-diff'] })
    },
  })

  if (isLoading) return <div className="text-gray-400">Loading...</div>

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Scans</h2>

      {/* New Scan */}
      <div className="card mb-6">
        <h3 className="text-lg font-semibold mb-4">Start a New Scan</h3>
        <div className="flex flex-wrap gap-3 items-center">
          <select
            value={selectedTargetId}
            onChange={(e) => setSelectedTargetId(e.target.value)}
            className="input-field max-w-sm"
          >
            <option value="">Select a target...</option>
            {targets?.map((t: any) => (
              <option key={t.id} value={t.id}>{t.name} ({t.url})</option>
            ))}
          </select>
          <button
            className="btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            disabled={!selectedTargetId || newScanMutation.isPending}
            onClick={() => newScanMutation.mutate(Number(selectedTargetId))}
          >
            <Plus className="w-4 h-4" />
            {newScanMutation.isPending ? 'Starting...' : 'Start Scan'}
          </button>
          {targets && targets.length === 0 && (
            <span className="text-sm text-gray-500">Add a target first.</span>
          )}
        </div>
        <div className="flex flex-wrap gap-4 items-center mt-3 pt-3 border-t border-gray-700">
          <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={evasionEnabled}
              onChange={(e) => setEvasionEnabled(e.target.checked)}
              className="w-4 h-4 accent-blue-600"
            />
            Request pacing
            <span className="text-gray-500">(rotate User-Agent, jitter between requests)</span>
          </label>
          <label className={`flex items-center gap-2 text-sm ${evasionEnabled ? 'text-gray-300' : 'text-gray-600'}`}>
            Delay override
            <input
              type="number"
              min="0"
              step="0.1"
              value={requestDelay}
              onChange={(e) => setRequestDelay(e.target.value)}
              disabled={!evasionEnabled}
              placeholder="default"
              className="input-field w-24 py-1 disabled:opacity-50"
            />
            <span className="text-gray-500">seconds</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={externalLookups}
              onChange={(e) => setExternalLookups(e.target.checked)}
              className="w-4 h-4 accent-blue-600"
            />
            External lookups
            <span className="text-gray-500">
              (NVD, crt.sh, ip-api.com, Spamhaus, WHOIS; sends target identifiers off-machine)
            </span>
          </label>
        </div>
        {newScanMutation.isError && (
          <div className="text-red-400 text-sm mt-3">
            {(newScanMutation.error as Error).message}. Check that the backend API is reachable.
          </div>
        )}
      </div>

      <div className="card">
        {scans && scans.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">ID</th>
                <th className="pb-3">Target</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Phase</th>
                <th className="pb-3">Progress</th>
                <th className="pb-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan: any) => (
                <tr key={scan.id} className="border-t border-gray-700">
                  <td className="py-3">#{scan.id}</td>
                  <td className="py-3">
                    <div className="font-medium">{targetById(scan.target_id)?.name || `Target #${scan.target_id}`}</div>
                    <div className="text-xs text-gray-500 font-mono">{targetById(scan.target_id)?.url}</div>
                  </td>
                  <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                  <td className="py-3 text-gray-400">{scan.current_phase || '-'}</td>
                  <td className="py-3 w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-signal h-2 rounded-full transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{Math.round(scan.progress)}%</span>
                    </div>
                  </td>
                  <td className="py-3">
                    <div className="flex gap-2">
                      {scan.status === 'pending' && (
                        <button
                          onClick={() => startMutation.mutate(scan.id)}
                          className="p-1 hover:bg-green-900 rounded text-green-400"
                          title="Start Scan"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                      )}
                      {scan.status === 'running' && (
                        <button
                          onClick={() => stopMutation.mutate(scan.id)}
                          className="p-1 hover:bg-red-900 rounded text-red-400"
                          title="Stop Scan"
                        >
                          <Square className="w-4 h-4" />
                        </button>
                      )}
                      {scan.status === 'completed' && (
                        <Link
                          to={`/reports/${scan.id}`}
                          className="p-1 hover:bg-blue-900 rounded text-blue-400"
                          title="View Report"
                        >
                          <FileText className="w-4 h-4" />
                        </Link>
                      )}
                      <Link
                        to={`/scans/${scan.id}`}
                        className="p-1 hover:bg-gray-700 rounded"
                        title="View Details"
                      >
                        <FileText className="w-4 h-4" />
                      </Link>
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete scan #${scan.id} and all of its results? This cannot be undone.`)) {
                            deleteMutation.mutate(scan.id)
                          }
                        }}
                        disabled={deleteMutation.isPending || scan.status === 'running' || scan.status === 'stopping'}
                        className="p-1 hover:bg-red-900 rounded text-red-400 disabled:opacity-30 disabled:cursor-not-allowed"
                        title="Delete Scan"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-8 text-gray-500">
            No scans yet. Start one above.
          </div>
        )}
      </div>
      {(startMutation.isError || stopMutation.isError || deleteMutation.isError) && (
        <div className="text-red-400 text-sm mt-3">
          {(deleteMutation.error as Error)?.message ||
            'Something went wrong updating that scan. Check that the backend API is reachable.'}
        </div>
      )}
    </div>
  )
}
