import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { FileText, Download } from 'lucide-react'

export default function ReportsList() {
  // The nav's "Reports" tab previously linked to /reports with no matching
  // route at all -- only /reports/:id (a single report) existed. This is
  // the missing list page: every completed scan has a report, so list
  // those with links into the existing single-report view.
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans')
      if (!res.ok) throw new Error('Failed to load scans')
      return res.json()
    },
    refetchInterval: 5000,
  })

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch('/api/targets')
      if (!res.ok) throw new Error('Failed to load targets')
      return res.json()
    },
  })

  const targetName = (targetId: number) =>
    targets?.find((t: any) => t.id === targetId)?.name || `Target #${targetId}`

  if (isLoading) return <div className="text-gray-400">Loading...</div>

  const reportable = (scans || []).filter((s: any) => s.status === 'completed' || s.status === 'stopped')

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Reports</h2>

      <div className="card">
        {reportable.length > 0 ? (
          <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">Scan</th>
                <th className="pb-3">Target</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Completed</th>
                <th className="pb-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reportable.map((scan: any) => (
                <tr key={scan.id} className="border-t border-gray-700">
                  <td className="py-3">#{scan.id}</td>
                  <td className="py-3">{targetName(scan.target_id)}</td>
                  <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                  <td className="py-3 text-gray-400">
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}
                  </td>
                  <td className="py-3">
                    <div className="flex gap-2">
                      <Link
                        to={`/reports/${scan.id}`}
                        className="p-1 hover:bg-blue-900 rounded text-blue-400"
                        title="View Report"
                      >
                        <FileText className="w-4 h-4" />
                      </Link>
                      <a
                        href={`/api/reports/${scan.id}/export/pdf`}
                        download
                        className="p-1 hover:bg-red-900 rounded text-red-400"
                        title="Download PDF"
                      >
                        <Download className="w-4 h-4" />
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            No reports yet -- reports appear here once a scan completes or is stopped.{' '}
            <Link to="/scans" className="text-blue-400 hover:underline">Go start one</Link>.
          </div>
        )}
      </div>
    </div>
  )
}
