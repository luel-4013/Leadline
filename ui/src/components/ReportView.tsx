import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, ChevronRight, ChevronDown } from 'lucide-react'
import { useState } from 'react'

export default function ReportView() {
  const { id } = useParams()
  const [expandedPhases, setExpandedPhases] = useState<number[]>([])

  const { data: report, isLoading } = useQuery({
    queryKey: ['report', id],
    queryFn: async () => {
      const res = await fetch(`/api/reports/${id}`)
      if (!res.ok) throw new Error('Report not found')
      return res.json()
    },
  })

  if (isLoading) return <div className="text-gray-400">Loading report...</div>
  if (!report) return <div className="text-red-400">Report not found</div>

  const togglePhase = (idx: number) => {
    setExpandedPhases(prev =>
      prev.includes(idx) ? prev.filter(i => i !== idx) : [...prev, idx]
    )
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Report - Scan #{id}</h2>
        <div className="flex gap-2">
          <a href={`/api/reports/${id}/export/json`} download className="btn-primary flex items-center gap-2">
            <Download className="w-4 h-4" /> JSON
          </a>
          <a href={`/api/reports/${id}/export/pdf`} download className="px-4 py-2 rounded-md bg-red-600 hover:bg-red-700 text-white flex items-center gap-2">
            <Download className="w-4 h-4" /> PDF
          </a>
          <a href={`/api/reports/${id}/export/markdown`} download className="px-4 py-2 rounded-md border border-gray-600 hover:bg-gray-700 flex items-center gap-2">
            <Download className="w-4 h-4" /> Markdown
          </a>
          <a href={`/api/reports/${id}/export/html`} download className="px-4 py-2 rounded-md border border-gray-600 hover:bg-gray-700 flex items-center gap-2">
            <Download className="w-4 h-4" /> HTML
          </a>
        </div>
      </div>

      {/* Risk Score -- the headline number before any detail */}
      <div className={`card mb-6 flex items-center gap-6 border-l-4 ${
        report.summary.risk_level === 'critical' ? 'border-l-red-500' :
        report.summary.risk_level === 'high' ? 'border-l-orange-500' :
        report.summary.risk_level === 'medium' ? 'border-l-yellow-500' :
        report.summary.risk_level === 'low' ? 'border-l-blue-500' : 'border-l-gray-600'
      }`}>
        <div className={`text-5xl font-bold font-display ${
          report.summary.risk_level === 'critical' ? 'text-red-400' :
          report.summary.risk_level === 'high' ? 'text-orange-400' :
          report.summary.risk_level === 'medium' ? 'text-yellow-400' :
          report.summary.risk_level === 'low' ? 'text-blue-400' : 'text-gray-400'
        }`}>
          {report.summary.risk_score}
        </div>
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide">Overall Risk</div>
          <div className="text-lg font-semibold uppercase">{report.summary.risk_level}</div>
          <div className="text-sm text-gray-500">
            Derived from the highest-severity findings present, not just total count.
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-9 gap-4 mb-8">
        <SummaryCard label="Endpoints" value={report.summary.total_endpoints} />
        <SummaryCard label="API Routes" value={report.summary.api_routes} />
        <SummaryCard label="Auth" value={report.summary.authentication_mechanisms} />
        <SummaryCard label="Debug" value={report.summary.debug_interfaces} />
        <SummaryCard label="Suspicious" value={report.summary.suspicious_parameters} color="text-yellow-400" />
        <SummaryCard label="Vulns" value={report.summary.possible_vulns} color="text-red-400" />
        <SummaryCard label="Missing" value={report.summary.missing_controls} color="text-orange-400" />
        <SummaryCard label="Open Ports" value={report.summary.open_ports_found} color="text-blue-400" />
        <SummaryCard label="High Risk" value={report.summary.high_risk_ports} color="text-red-400" />
        <SummaryCard label="CVE Candidates" value={report.summary.cves_found} color="text-rose-400" />
        <SummaryCard label="Verified CVEs" value={report.summary.verified_cves} color="text-orange-400" />
        <SummaryCard label="Critical CVE Candidates" value={report.summary.critical_cves} color="text-red-500" />
      </div>

      {/* Target Info */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold mb-4">Target Information</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-gray-400 text-sm">Name:</span>
            <p className="font-medium">{report.target_name}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">URL:</span>
            <p className="font-medium text-blue-400">{report.target_url}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Status:</span>
            <p className={`font-medium status-${report.status}`}>{report.status}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Completed:</span>
            <p className="font-medium">{report.completed_at ? new Date(report.completed_at).toLocaleString() : 'N/A'}</p>
          </div>
        </div>
      </div>

      {/* Highlights: the specific phase details worth surfacing directly
          rather than making the reader expand raw JSON to find them */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {(report.highlights?.technologies?.length > 0 || report.highlights?.response_headers || report.highlights?.cdn_waf?.length > 0) && (
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Technology &amp; Server</h3>
            {report.highlights.cdn_waf?.length > 0 && (
              <div className="mb-4">
                <span className="text-gray-400 text-sm">CDN / WAF detected:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.cdn_waf.map((c: string) => (
                    <span key={c} className="px-2 py-1 bg-purple-900/50 text-purple-300 rounded text-xs">{c}</span>
                  ))}
                </div>
              </div>
            )}
            {report.highlights.technologies?.length > 0 && (
              <div className="mb-4">
                <span className="text-gray-400 text-sm">Detected technologies:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.technologies.map((t: string) => (
                    <span key={t} className="px-2 py-1 bg-blue-900/50 text-blue-300 rounded text-xs">{t}</span>
                  ))}
                </div>
              </div>
            )}
            {report.highlights.response_headers && (
              <div>
                <span className="text-gray-400 text-sm">Response headers:</span>
                <div className="mt-2 font-mono text-xs text-gray-300 bg-gray-900 rounded p-3 space-y-1">
                  {Object.entries(report.highlights.response_headers).map(([k, v]) => (
                    <div key={k}><span className="text-gray-500">{k}:</span> {String(v)}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {(report.highlights?.security_headers_present?.length > 0 || report.highlights?.security_headers_missing?.length > 0) && (
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Security Headers</h3>
            {report.highlights.security_headers_present?.length > 0 && (
              <div className="mb-3">
                <span className="text-green-400 text-sm">Present:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.security_headers_present.map((h: string) => (
                    <span key={h} className="px-2 py-1 bg-green-900/50 text-green-300 rounded text-xs">{h}</span>
                  ))}
                </div>
              </div>
            )}
            {report.highlights.security_headers_missing?.length > 0 && (
              <div>
                <span className="text-orange-400 text-sm">Missing:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.security_headers_missing.map((h: string) => (
                    <span key={h} className="px-2 py-1 bg-orange-900/50 text-orange-300 rounded text-xs">{h}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {(report.highlights?.resolved_ips?.length > 0 || report.highlights?.geolocation || report.highlights?.whois || report.highlights?.subdomains?.length > 0 || report.highlights?.dnssec_enabled !== null) && (
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">DNS, WHOIS &amp; Geolocation</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              {report.highlights.resolved_ips?.length > 0 && (
                <div><span className="text-gray-400">Resolved IPs:</span> <span className="font-mono">{report.highlights.resolved_ips.join(', ')}</span></div>
              )}
              {report.highlights.hostnames?.length > 0 && (
                <div><span className="text-gray-400">Hostnames:</span> <span className="font-mono">{report.highlights.hostnames.join(', ')}</span></div>
              )}
              {report.highlights.geolocation?.country && (
                <div><span className="text-gray-400">Location:</span> {report.highlights.geolocation.city ? `${report.highlights.geolocation.city}, ` : ''}{report.highlights.geolocation.country}</div>
              )}
              {(report.highlights.geolocation?.isp || report.highlights.geolocation?.org) && (
                <div><span className="text-gray-400">ISP/Org:</span> {report.highlights.geolocation.isp || report.highlights.geolocation.org}</div>
              )}
              {report.highlights.geolocation?.asn && (
                <div><span className="text-gray-400">ASN:</span> {report.highlights.geolocation.asn}</div>
              )}
              {report.highlights.whois?.parsed?.registrar && (
                <div><span className="text-gray-400">Registrar:</span> {report.highlights.whois.parsed.registrar}</div>
              )}
              {report.highlights.whois?.parsed?.creation_date && (
                <div><span className="text-gray-400">Registered:</span> {report.highlights.whois.parsed.creation_date}</div>
              )}
              {report.highlights.dnssec_enabled !== null && report.highlights.dnssec_enabled !== undefined && (
                <div><span className="text-gray-400">DNSSEC:</span> {report.highlights.dnssec_enabled ? 'Enabled' : 'Not enabled'}</div>
              )}
              {report.highlights.ip_reputation && report.highlights.ip_reputation.listed !== null && report.highlights.ip_reputation.listed !== undefined && (
                <div>
                  <span className="text-gray-400">IP Reputation:</span>{' '}
                  <span className={report.highlights.ip_reputation.listed ? 'text-red-400' : 'text-green-400'}>
                    {report.highlights.ip_reputation.listed ? 'Listed (Spamhaus)' : 'Clean'}
                  </span>
                </div>
              )}
            </div>
            {report.highlights.subdomains?.length > 0 && (
              <div className="mt-3">
                <span className="text-gray-400 text-sm">Subdomains found ({report.highlights.subdomains.length}):</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.subdomains.slice(0, 20).map((s: string) => (
                    <span key={s} className="px-2 py-1 bg-gray-700 rounded text-xs font-mono">{s}</span>
                  ))}
                  {report.highlights.subdomains.length > 20 && (
                    <span className="px-2 py-1 text-xs text-gray-500">+{report.highlights.subdomains.length - 20} more</span>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {report.highlights?.open_ports && Object.keys(report.highlights.open_ports).length > 0 && (
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Open Ports</h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-400">
                  <th className="pb-2">Port</th><th className="pb-2">Service</th><th className="pb-2">Detail</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(report.highlights.open_ports).map(([port, info]: [string, any]) => (
                  <tr key={port} className="border-t border-gray-700">
                    <td className="py-2 font-mono">{port}</td>
                    <td className="py-2">{info.service}</td>
                    <td className="py-2 text-gray-400 text-xs truncate max-w-xs">
                      {info.version_guess || info.tls?.subject_cn || info.banner?.slice(0, 60) || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {(report.highlights?.cve_matches?.length > 0 || report.highlights?.cve_lookup_note) && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold mb-2">
              CVE Correlations <span className="text-gray-500 text-sm font-normal">(CPE version checks where resolved; keyword candidates otherwise)</span>
            </h3>
            {report.highlights.cve_lookup_note && (
              <p className="text-xs text-yellow-500 bg-yellow-900/20 border border-yellow-900/40 rounded px-3 py-2 mb-4">
                ⚠ {report.highlights.cve_lookup_note}
              </p>
            )}
            <div className="space-y-3">
              {report.highlights.cve_matches.map((cve: any) => (
                <div key={cve.cve_id} className="border-t border-gray-700 pt-3 first:border-t-0 first:pt-0">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${
                        cve.cvss_severity === 'critical' ? 'bg-red-900/60 text-red-300' :
                        cve.cvss_severity === 'high' ? 'bg-orange-900/60 text-orange-300' :
                        cve.cvss_severity === 'medium' ? 'bg-yellow-900/60 text-yellow-300' :
                        'bg-gray-700 text-gray-300'
                      }`}>
                        {cve.cvss_severity || 'unscored'}{cve.cvss_score ? ` ${cve.cvss_score}` : ''}
                      <span className="ml-2 text-xs font-normal text-gray-500">
                        {cve.applicability_verified ? 'CPE range' : 'keyword only'}
                      </span>
                      </span>
                      <span className="font-mono font-semibold">{cve.cve_id}</span>
                      <span className="text-gray-400 text-sm">{cve.product} {cve.version}</span>
                    </div>
                    <div className="flex gap-3 text-xs">
                      <a href={cve.nvd_url} target="_blank" rel="noopener noreferrer" className="text-signal hover:underline">NVD →</a>
                      <a href={cve.exploitdb_search_url} target="_blank" rel="noopener noreferrer" className="text-rose-400 hover:underline">ExploitDB →</a>
                    </div>
                  </div>
                  {cve.description && <p className="text-sm text-gray-400 mt-1">{cve.description}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {(report.highlights?.discovered_endpoints?.length > 0 || report.highlights?.api_documentation?.length > 0 || report.highlights?.url_parameters?.length > 0) && (
          <div className="card lg:col-span-2">
            <h3 className="text-lg font-semibold mb-4">Discovered Attack Surface</h3>
            {report.highlights.api_documentation?.length > 0 && (
              <div className="mb-4">
                <span className="text-orange-400 text-sm">⚠ Exposed API documentation:</span>
                <div className="mt-2 space-y-1">
                  {report.highlights.api_documentation.map((url: string) => (
                    <div key={url} className="font-mono text-xs text-gray-300 truncate">{url}</div>
                  ))}
                </div>
              </div>
            )}
            {report.highlights.discovered_endpoints?.length > 0 && (
              <div className="mb-4">
                <span className="text-gray-400 text-sm">Endpoints found ({report.highlights.discovered_endpoints.length}, from API probing + JS analysis):</span>
                <div className="mt-2 max-h-48 overflow-y-auto font-mono text-xs text-gray-300 bg-gray-900 rounded p-3 space-y-0.5">
                  {report.highlights.discovered_endpoints.map((url: string) => (
                    <div key={url} className="truncate">{url}</div>
                  ))}
                </div>
              </div>
            )}
            {report.highlights.url_parameters?.length > 0 && (
              <div>
                <span className="text-gray-400 text-sm">URL/form parameters seen:</span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {report.highlights.url_parameters.map((p: string) => (
                    <span key={p} className="px-2 py-1 bg-gray-700 rounded text-xs font-mono">{p}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Phases */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold mb-4">Reconnaissance Phases</h3>
        {report.phases.map((phase: any, idx: number) => (
          <div key={idx} className="border-b border-gray-700 last:border-0">
            <button
              onClick={() => togglePhase(idx)}
              className="w-full flex items-center justify-between py-3 hover:bg-gray-700 px-2 rounded transition-colors"
            >
              <div className="flex items-center gap-3">
                {expandedPhases.includes(idx) ? (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                )}
                <span className="font-medium">{phase.phase_name}</span>
                <span className={`status-${phase.status}`}>{phase.status}</span>
              </div>
              <span className="text-gray-400 text-sm">{phase.findings_count} findings</span>
            </button>
            {expandedPhases.includes(idx) && phase.data && (
              <div className="p-4 bg-gray-900 rounded mb-3 ml-8">
                <pre className="text-xs text-gray-300 overflow-auto max-h-64">
                  {JSON.stringify(phase.data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Endpoints */}
      {report.endpoints && report.endpoints.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Discovered Endpoints ({report.endpoints.length})</h3>
          <div className="max-h-64 overflow-auto">
            <ul className="space-y-1">
              {report.endpoints.map((ep: string, idx: number) => (
                <li key={idx} className="font-mono text-sm text-gray-300 bg-gray-900 px-2 py-1 rounded">
                  {ep}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

function SummaryCard({ label, value, color = 'text-white' }: { label: string, value: number, color?: string }) {
  return (
    <div className="card text-center">
      <h4 className="text-gray-400 text-xs uppercase mb-1">{label}</h4>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}
