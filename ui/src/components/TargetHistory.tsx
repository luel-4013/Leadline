import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ArrowLeft, Check, Clock, GitCompare,
  RotateCcw, Target as TargetIcon, Trash2, X,
} from 'lucide-react'

const TERMINAL = ['completed', 'stopped']

function severityClass(severity?: string) {
  switch (severity) {
    case 'critical': return 'bg-red-900/60 text-red-300'
    case 'high': return 'bg-orange-900/60 text-orange-300'
    case 'medium': return 'bg-yellow-900/60 text-yellow-300'
    case 'low': return 'bg-blue-900/60 text-blue-300'
    default: return 'bg-gray-700 text-gray-300'
  }
}

function riskClass(level?: string) {
  switch (level) {
    case 'critical': return 'text-red-400'
    case 'high': return 'text-orange-400'
    case 'medium': return 'text-yellow-400'
    case 'low': return 'text-blue-400'
    default: return 'text-gray-400'
  }
}

function formatDate(value?: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

function formatDuration(seconds?: number | null) {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${seconds % 60}s`
}

function Stat({ label, value, className = '' }: { label: string; value: any; className?: string }) {
  return (
    <div className="card">
      <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">{label}</div>
      <div className={`text-2xl font-bold ${className}`}>{value ?? '—'}</div>
    </div>
  )
}

function Empty({ children }: { children: any }) {
  return <p className="text-sm text-gray-500">{children}</p>
}

function StringList({ items, tone = 'text-gray-300' }: { items?: string[]; tone?: string }) {
  if (!items?.length) return <Empty>None</Empty>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item, index) => (
        <span key={`${item}-${index}`} className={`font-mono text-xs px-2 py-1 rounded bg-white/5 ${tone}`}>{item}</span>
      ))}
    </div>
  )
}

function TriageButtons({ finding }: { finding: any }) {
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: async (triage_status: string) => {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ triage_status }),
      })
      if (!res.ok) throw new Error('Failed to update triage state')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['target-history'] })
      queryClient.invalidateQueries({ queryKey: ['target-diff'] })
    },
  })

  const status = finding.triage_status || 'open'
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded ${
        status === 'false_positive' ? 'bg-gray-700 text-gray-400'
        : status === 'acknowledged' ? 'bg-emerald-900/50 text-emerald-300'
        : 'bg-white/5 text-gray-400'
      }`}>
        {status.replace('_', ' ')}
      </span>
      <button
        title="Acknowledge"
        disabled={mutation.isPending || status === 'acknowledged'}
        onClick={() => mutation.mutate('acknowledged')}
        className="p-1 rounded hover:bg-emerald-900/40 text-emerald-400 disabled:opacity-30"
      >
        <Check className="w-3.5 h-3.5" />
      </button>
      <button
        title="Mark false positive"
        disabled={mutation.isPending || status === 'false_positive'}
        onClick={() => mutation.mutate('false_positive')}
        className="p-1 rounded hover:bg-gray-700 text-gray-400 disabled:opacity-30"
      >
        <X className="w-3.5 h-3.5" />
      </button>
      <button
        title="Reopen"
        disabled={mutation.isPending || status === 'open'}
        onClick={() => mutation.mutate('open')}
        className="p-1 rounded hover:bg-blue-900/40 text-blue-400 disabled:opacity-30"
      >
        <RotateCcw className="w-3.5 h-3.5" />
      </button>
      {mutation.isError && (
        <span className="text-[10px] text-red-400">Update failed</span>
      )}
    </div>
  )
}

function FindingCard({ finding, removed = false }: { finding: any; removed?: boolean }) {
  return (
    <div className={`border border-white/5 rounded-lg p-3 ${removed ? 'opacity-60' : 'bg-white/[0.02]'}`}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${severityClass(finding.severity)}`}>
            {finding.severity || 'info'}
          </span>
          <span className="font-medium text-sm">{finding.title}</span>
        </div>
        {!removed && <TriageButtons finding={finding} />}
      </div>
      {finding.location && <div className="text-xs font-mono text-gray-500 mt-1">{finding.location}</div>}
      {finding.description && <p className="text-xs text-gray-400 mt-2 line-clamp-3">{finding.description}</p>}
      {finding.metadata?.applicability_verified != null && (
        <div className="text-[10px] text-gray-500 mt-1">
          {finding.metadata.applicability_verified ? 'CPE version range verified' : 'NVD keyword candidate (unverified)'}
        </div>
      )}
    </div>
  )
}

function DiffView({ diff, isCustom }: { diff: any; isCustom: boolean }) {
  const [tab, setTab] = useState<'findings' | 'infrastructure' | 'endpoints'>('findings')
  const summary = diff?.summary || {}
  const findings = diff?.findings || { new: [], removed: [], changed: [] }

  return (
    <div>
      <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-signal" />
            {isCustom ? 'Selected comparison' : 'Changes since previous scan'}
          </h3>
          <p className="text-xs text-gray-500">
            Scan #{diff?.from_scan?.scan_id} ({formatDate(diff?.from_scan?.created_at)}) → Scan #{diff?.to_scan?.scan_id} ({formatDate(diff?.to_scan?.created_at)})
          </p>
        </div>
        <div className="flex gap-2 flex-wrap text-xs">
          <span className="px-2 py-1 rounded bg-emerald-900/30 text-emerald-300">+{summary.new_findings || 0} new findings</span>
          <span className="px-2 py-1 rounded bg-red-900/30 text-red-300">-{summary.removed_findings || 0} removed</span>
          <span className="px-2 py-1 rounded bg-yellow-900/30 text-yellow-300">{summary.changed_findings || 0} changed</span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <Stat label="Ports opened" value={summary.ports_opened} className="text-emerald-400" />
        <Stat label="Ports closed" value={summary.ports_closed} className="text-red-400" />
        <Stat label="Endpoints added" value={summary.endpoints_added} className="text-blue-400" />
        <Stat label="IPs changed" value={(summary.ips_added || 0) + (summary.ips_removed || 0)} className="text-yellow-400" />
      </div>

      <div className="flex gap-2 border-b border-white/5 mb-4">
        {(['findings', 'infrastructure', 'endpoints'] as const).map((value) => (
          <button
            key={value}
            onClick={() => setTab(value)}
            className={`px-3 py-2 text-sm capitalize -mb-px border-b-2 ${
              tab === value ? 'border-signal text-signal' : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {value}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <div className="space-y-6">
          <section>
            <h4 className="text-sm font-semibold mb-2 text-emerald-400">New ({findings.new.length})</h4>
            {findings.new.length === 0 ? <Empty>No new findings.</Empty> : (
              <div className="space-y-2">
                {findings.new.map((finding: any) => <FindingCard key={finding.key} finding={finding} />)}
              </div>
            )}
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2 text-red-400">Removed ({findings.removed.length})</h4>
            {findings.removed.length === 0 ? <Empty>No findings disappeared.</Empty> : (
              <div className="space-y-2">
                {findings.removed.map((finding: any) => <FindingCard key={finding.key} finding={finding} removed />)}
              </div>
            )}
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2 text-yellow-400">Changed ({findings.changed.length})</h4>
            {findings.changed.length === 0 ? <Empty>No finding values changed.</Empty> : (
              <div className="space-y-2">
                {findings.changed.map((change: any) => (
                  <div key={change.key} className="border border-white/5 rounded-lg p-3">
                    <FindingCard finding={change.after} />
                    <div className="mt-2 text-xs text-gray-400 space-y-1">
                      {change.changes.map((item: any) => (
                        <div key={item.field}>
                          <span className="text-gray-500">{item.field}:</span> {String(item.before)} → {String(item.after)}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {tab === 'infrastructure' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <section>
            <h4 className="text-sm font-semibold mb-2">Ports opened</h4>
            <StringList items={(diff.ports?.opened || []).map((port: string) => String(port))} tone="text-emerald-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Ports closed</h4>
            <StringList items={(diff.ports?.closed || []).map((port: string) => String(port))} tone="text-red-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Ports changed</h4>
            {diff.ports?.changed?.length ? (
              <div className="space-y-1 text-xs">
                {diff.ports.changed.map((item: any) => (
                  <div key={item.port} className="font-mono text-gray-300">
                    {item.port}: {item.before?.service} → {item.after?.service}
                    {item.after?.version ? ` (${item.after.version})` : ''}
                  </div>
                ))}
              </div>
            ) : <Empty>None</Empty>}
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Resolved IPs added</h4>
            <StringList items={diff.resolved_ips?.added} tone="text-emerald-300" />
            <div className="h-3" />
            <h4 className="text-sm font-semibold mb-2">Resolved IPs removed</h4>
            <StringList items={diff.resolved_ips?.removed} tone="text-red-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Subdomains added</h4>
            <StringList items={diff.subdomains?.added} tone="text-emerald-300" />
            <div className="h-3" />
            <h4 className="text-sm font-semibold mb-2">Subdomains removed</h4>
            <StringList items={diff.subdomains?.removed} tone="text-red-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Technologies added</h4>
            <StringList items={diff.technologies?.added} tone="text-emerald-300" />
            <div className="h-3" />
            <h4 className="text-sm font-semibold mb-2">Technologies removed</h4>
            <StringList items={diff.technologies?.removed} tone="text-red-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">CDN/WAF added</h4>
            <StringList items={diff.cdn_waf?.added} tone="text-emerald-300" />
            <div className="h-3" />
            <h4 className="text-sm font-semibold mb-2">CDN/WAF removed</h4>
            <StringList items={diff.cdn_waf?.removed} tone="text-red-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">DNS record changes</h4>
            {Object.keys(diff.dns_records?.added || {}).length || Object.keys(diff.dns_records?.removed || {}).length ? (
              <div className="space-y-1 text-xs font-mono">
                {Object.entries(diff.dns_records?.added || {}).map(([type, values]: any) => (
                  <div key={`a-${type}`} className="text-emerald-300">+ {type}: {(values || []).join(', ')}</div>
                ))}
                {Object.entries(diff.dns_records?.removed || {}).map(([type, values]: any) => (
                  <div key={`r-${type}`} className="text-red-300">- {type}: {(values || []).join(', ')}</div>
                ))}
              </div>
            ) : <Empty>No DNS record changes.</Empty>}
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">WHOIS changes</h4>
            {Object.keys(diff.whois || {}).length ? (
              <div className="space-y-1 text-xs">
                {Object.entries(diff.whois).map(([field, change]: any) => (
                  <div key={field} className="text-gray-300">
                    <span className="text-gray-500">{field}:</span> {String(change.before ?? '—')} → {String(change.after ?? '—')}
                  </div>
                ))}
              </div>
            ) : <Empty>No WHOIS changes.</Empty>}
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">DNSSEC</h4>
            <p className="text-sm text-gray-300">
              {diff.dnssec?.changed
                ? `${diff.dnssec.before == null ? 'unknown' : diff.dnssec.before} → ${diff.dnssec.after == null ? 'unknown' : diff.dnssec.after}`
                : 'No change'}
            </p>
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2">Security headers added / removed</h4>
            <StringList items={diff.security_headers_present?.added} tone="text-emerald-300" />
            <div className="h-3" />
            <StringList items={diff.security_headers_present?.removed} tone="text-red-300" />
          </section>
        </div>
      )}

      {tab === 'endpoints' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <section>
            <h4 className="text-sm font-semibold mb-2 text-emerald-400">Added ({diff.endpoints?.added?.length || 0})</h4>
            <StringList items={diff.endpoints?.added} tone="text-emerald-300" />
          </section>
          <section>
            <h4 className="text-sm font-semibold mb-2 text-red-400">Removed ({diff.endpoints?.removed?.length || 0})</h4>
            <StringList items={diff.endpoints?.removed} tone="text-red-300" />
          </section>
        </div>
      )}
    </div>
  )
}

export default function TargetHistory() {
  const { id } = useParams()
  const targetId = Number(id)
  const queryClient = useQueryClient()
  const [selection, setSelection] = useState<{ from: number; to: number } | null>(null)

  const { data: history, isLoading, error } = useQuery({
    queryKey: ['target-history', targetId],
    queryFn: async () => {
      const res = await fetch(`/api/targets/${targetId}/history`)
      if (!res.ok) throw new Error('Failed to load target history')
      return res.json()
    },
    enabled: Number.isFinite(targetId),
    refetchInterval: 5000,
  })

  const scans = history?.scans || []
  const terminal = scans.filter((scan: any) => TERMINAL.includes(scan.status))

  const { data: customDiff, isFetching: diffLoading } = useQuery({
    queryKey: ['target-diff', targetId, selection?.from, selection?.to],
    queryFn: async () => {
      const res = await fetch(
        `/api/targets/${targetId}/history/diff?from_scan_id=${selection?.from}&to_scan_id=${selection?.to}`
      )
      if (!res.ok) throw new Error('Failed to load comparison')
      return res.json()
    },
    enabled: Boolean(selection?.from && selection?.to && selection.from !== selection.to),
  })

  const deleteMutation = useMutation({
    mutationFn: async (scanId: number) => {
      const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' })
      if (!res.ok) {
        const body = await res.json().catch(() => null)
        throw new Error(body?.detail || 'Failed to delete scan')
      }
    },
    onSuccess: () => {
      setSelection(null)
      queryClient.invalidateQueries({ queryKey: ['target-history'] })
      queryClient.invalidateQueries({ queryKey: ['target-diff'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const diff = selection ? customDiff : history?.latest_diff
  const activeFrom = selection?.from ?? history?.latest_diff?.from_scan?.scan_id
  const activeTo = selection?.to ?? history?.latest_diff?.to_scan?.scan_id

  if (isLoading) return <div className="text-gray-400">Loading target history...</div>
  if (error || !history) {
    return (
      <div className="card">
        <p className="text-red-400">{(error as Error)?.message || 'Target not found.'}</p>
        <Link to="/targets" className="text-signal text-sm hover:underline">← Back to targets</Link>
      </div>
    )
  }

  const target = history.target
  const latest = scans[scans.length - 1]
  const latestRisk = history.latest_diff?.to_scan || latest

  const updateSelection = (which: 'from' | 'to', value: number) => {
    const from = selection?.from ?? activeFrom
    const to = selection?.to ?? activeTo
    if (from == null || to == null) return
    let next = which === 'from' ? { from: value, to } : { from, to: value }
    if (next.from === next.to) {
      const other = terminal.find((scan: any) => scan.scan_id !== value)
      if (other) {
        if (which === 'from') next = { ...next, to: other.scan_id }
        else next = { ...next, from: other.scan_id }
      }
    }
    setSelection(next)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <Link to="/targets" className="text-xs text-gray-500 hover:text-signal flex items-center gap-1 mb-2">
            <ArrowLeft className="w-3 h-3" /> Targets
          </Link>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <TargetIcon className="w-5 h-5 text-signal" />
            {target.name}
          </h2>
          <p className="text-sm font-mono text-gray-400">{target.url}</p>
        </div>
        <div className="flex gap-2">
          <Link to={`/targets/${target.id}/edit`} className="btn-primary text-sm">Edit target</Link>
          <button
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['target-history'] })
              queryClient.invalidateQueries({ queryKey: ['target-diff'] })
            }}
            className="btn-secondary text-sm flex items-center gap-2"
          >
            <Clock className="w-4 h-4" /> Refresh
          </button>
        </div>
      </div>

      {target.notes && (
        <div className="card">
          <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Notes</div>
          <p className="text-sm text-gray-300 whitespace-pre-wrap">{target.notes}</p>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Total scans" value={history.totals.scans} />
        <Stat label="Completed" value={history.totals.completed} className="text-emerald-400" />
        <Stat label="Latest risk" value={latestRisk?.risk_score != null ? `${latestRisk.risk_score}/100` : '—'} className={riskClass(latestRisk?.risk_level)} />
        <Stat label="Latest findings" value={latestRisk?.finding_count} />
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Activity className="w-4 h-4 text-signal" /> Scan timeline
          </h3>
          <span className="text-xs text-gray-500">History is kept until you delete a scan or the target.</span>
        </div>
        {scans.length === 0 ? (
          <Empty>No scans yet. Start one from the Scans page.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-xs uppercase tracking-wide">
                  <th className="pb-3">Scan</th>
                  <th className="pb-3">When</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Risk</th>
                  <th className="pb-3">Findings</th>
                  <th className="pb-3">Change vs previous</th>
                  <th className="pb-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {[...scans].reverse().map((scan: any) => {
                  const previous = [...terminal].reverse().find((item: any) => item.scan_id < scan.scan_id)
                  const canCompare = Boolean(previous && TERMINAL.includes(scan.status))
                  return (
                    <tr key={scan.scan_id} className="border-t border-white/5 align-top">
                      <td className="py-3">
                        <div className="font-medium">#{scan.scan_id}</div>
                        {scan.changes && (
                          <div className="text-[11px] text-gray-500">
                            +{scan.changes.new_findings} / -{scan.changes.removed_findings} findings
                          </div>
                        )}
                      </td>
                      <td className="py-3 text-gray-400 text-sm">
                        <div>{formatDate(scan.created_at)}</div>
                        <div className="text-xs text-gray-500">{formatDuration(scan.duration_seconds)}</div>
                      </td>
                      <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                      <td className={`py-3 font-semibold ${riskClass(scan.risk_level)}`}>
                        {scan.risk_score}/100
                        <div className="text-[10px] uppercase text-gray-500">{scan.risk_level}</div>
                      </td>
                      <td className="py-3 text-sm">
                        <div>{scan.finding_count} total</div>
                        <div className="text-[11px] text-gray-500">
                          {scan.severity_counts?.high || 0} high / {scan.severity_counts?.critical || 0} critical
                        </div>
                        {scan.unverified_cves > 0 && (
                          <div className="text-[11px] text-yellow-500">{scan.unverified_cves} unverified CVE candidates</div>
                        )}
                      </td>
                      <td className="py-3 text-xs text-gray-400">
                        {scan.changes ? (
                          <div className="space-y-0.5">
                            <div>Ports +{scan.changes.ports_opened} / -{scan.changes.ports_closed}</div>
                            <div>Endpoints +{scan.changes.endpoints_added} / -{scan.changes.endpoints_removed}</div>
                          </div>
                        ) : '—'}
                      </td>
                      <td className="py-3">
                        <div className="flex items-center gap-2 text-xs">
                          <Link to={`/scans/${scan.scan_id}`} className="text-signal hover:underline">Scan</Link>
                          {TERMINAL.includes(scan.status) && (
                            <Link to={`/reports/${scan.scan_id}`} className="text-signal hover:underline">Report</Link>
                          )}
                          {canCompare && (
                            <button
                              onClick={() => setSelection({ from: previous.scan_id, to: scan.scan_id })}
                              className="text-gray-400 hover:text-white flex items-center gap-1"
                            >
                              <GitCompare className="w-3 h-3" /> Diff
                            </button>
                          )}
                          <button
                            onClick={() => {
                              if (window.confirm(`Delete scan #${scan.scan_id} and all of its results? This cannot be undone.`)) {
                                deleteMutation.mutate(scan.scan_id)
                              }
                            }}
                            disabled={deleteMutation.isPending || scan.status === 'running' || scan.status === 'stopping'}
                            className="text-red-400 hover:text-red-300 disabled:opacity-30 disabled:cursor-not-allowed"
                            title="Delete scan"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {deleteMutation.isError && (
          <div className="text-red-400 text-sm mt-3">
            {(deleteMutation.error as Error).message}
          </div>
        )}
      </div>

      {terminal.length >= 2 && (
        <div className="card">
          <div className="flex items-end gap-3 flex-wrap mb-5">
            <div>
              <label className="block text-xs text-gray-500 uppercase tracking-wide mb-1">Compare from</label>
              <select
                value={activeFrom || ''}
                onChange={(e) => updateSelection('from', Number(e.target.value))}
                className="input-field py-1.5 text-sm"
              >
                {terminal.map((scan: any) => (
                  <option key={scan.scan_id} value={scan.scan_id}>#{scan.scan_id} — {formatDate(scan.created_at)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-500 uppercase tracking-wide mb-1">Compare to</label>
              <select
                value={activeTo || ''}
                onChange={(e) => updateSelection('to', Number(e.target.value))}
                className="input-field py-1.5 text-sm"
              >
                {terminal.map((scan: any) => (
                  <option key={scan.scan_id} value={scan.scan_id}>#{scan.scan_id} — {formatDate(scan.created_at)}</option>
                ))}
              </select>
            </div>
            {selection && (
              <button onClick={() => setSelection(null)} className="text-xs text-gray-400 hover:text-white pb-2">
                Reset to latest
              </button>
            )}
          </div>

          {diffLoading && <p className="text-sm text-gray-400">Loading comparison...</p>}
          {diff ? <DiffView diff={diff} isCustom={Boolean(selection)} /> : <Empty>Select two scans to compare.</Empty>}
        </div>
      )}

      {terminal.length < 2 && (
        <div className="card">
          <h3 className="text-lg font-semibold flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" /> Not enough history for a diff yet
          </h3>
          <p className="text-sm text-gray-400">
            Run a second scan of this target to see new/removed findings, port changes,
            DNS changes, and endpoint drift.
          </p>
        </div>
      )}
    </div>
  )
}
