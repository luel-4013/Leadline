import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, Edit, Trash2, History } from 'lucide-react'

export default function TargetsList() {
  const queryClient = useQueryClient()

  const { data: targets, isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch('/api/targets')
      return res.json()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await fetch(`/api/targets/${id}`, { method: 'DELETE' })
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        throw new Error(body?.detail || 'Failed to delete target')
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['target-history'] })
      queryClient.invalidateQueries({ queryKey: ['target-diff'] })
    },
  })

  if (isLoading) return <div className="text-gray-400">Loading...</div>

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Targets</h2>
        <Link to="/targets/new" className="btn-primary flex items-center gap-2">
          <Plus className="w-5 h-5" />
          Add Target
        </Link>
      </div>

      <div className="card">
        {targets && targets.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">ID</th>
                <th className="pb-3">Name</th>
                <th className="pb-3">URL</th>
                <th className="pb-3">Created</th>
                <th className="pb-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target: any) => (
                <tr key={target.id} className="border-t border-gray-700">
                  <td className="py-3">#{target.id}</td>
                  <td className="py-3 font-medium">
                    <Link to={`/targets/${target.id}`} className="hover:text-signal">{target.name}</Link>
                  </td>
                  <td className="py-3 text-blue-400">
                    <Link to={`/targets/${target.id}`} className="hover:underline">{target.url}</Link>
                  </td>
                  <td className="py-3 text-gray-400">
                    {new Date(target.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-3">
                    <div className="flex gap-2">
                      <Link
                        to={`/targets/${target.id}`}
                        className="p-1 hover:bg-gray-700 rounded text-signal"
                        title="History"
                      >
                        <History className="w-4 h-4" />
                      </Link>
                      <Link
                        to={`/targets/${target.id}/edit`}
                        className="p-1 hover:bg-gray-700 rounded"
                      >
                        <Edit className="w-4 h-4" />
                      </Link>
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete "${target.name}" and all of its scan history? This cannot be undone.`)) {
                            deleteMutation.mutate(target.id)
                          }
                        }}
                        disabled={deleteMutation.isPending}
                        className="p-1 hover:bg-red-900 rounded text-red-400 disabled:opacity-30 disabled:cursor-not-allowed"
                        title="Delete Target"
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
            No targets yet. Click "Add Target" to create one.
          </div>
        )}
      </div>
      {deleteMutation.isError && (
        <div className="text-red-400 text-sm mt-3">
          {(deleteMutation.error as Error).message}
        </div>
      )}
    </div>
  )
}
