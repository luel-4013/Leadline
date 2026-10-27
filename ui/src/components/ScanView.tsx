import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'

export default function ScanView() {
  const { id } = useParams()

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => {
      const res = await fetch(`/api/scans/${id}`)
      return res.json()
    },
    refetchInterval: 2000,
  })

  const { data: events } = useQuery({
    queryKey: ['scan-events', id],
    queryFn: async () => {
      const res = await fetch(`/api/reports/${id}`)
      if (!res.ok) return []
      const report = await res.json()
      return report.phases || []
    },
    enabled: !!scan?.status,
  })

  if (isLoading) return <div className="text-gray-400">Loading...</div>
  if (!scan) return <div className="text-red-400">Scan not found</div>

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Scan #{scan.id}</h2>

      <div className="grid grid-cols-2 gap-6 mb-8">
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Status</h3>
          <p className={`text-xl font-bold status-${scan.status}`}>{scan.status}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Progress</h3>
          <p className="text-xl font-bold">{Math.round(scan.progress)}%</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Current Phase</h3>
          <p className="text-xl font-bold">{scan.current_phase || 'Not started'}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Target ID</h3>
          <p className="text-xl font-bold">#{scan.target_id}</p>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Phase Results</h3>
        {events && events.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">Phase</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Findings</th>
              </tr>
            </thead>
            <tbody>
              {events.map((phase: any, idx: number) => (
                <tr key={idx} className="border-t border-gray-700">
                  <td className="py-3">{phase.phase_name}</td>
                  <td className={`py-3 status-${phase.status}`}>{phase.status}</td>
                  <td className="py-3">{phase.findings_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-500">No phase results yet.</p>
        )}
      </div>
    </div>
  )
}
