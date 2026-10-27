import { Routes, Route, NavLink, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useState, useEffect } from 'react'
import TargetsList from './components/TargetsList'
import TargetForm from './components/TargetForm'
import TargetHistory from './components/TargetHistory'
import ScansList from './components/ScansList'
import ScanView from './components/ScanView'
import ReportsList from './components/ReportsList'
import ReportView from './components/ReportView'
import { Shield, Target, Activity, FileText, Palette } from 'lucide-react'

const navItems = [
  { to: '/', icon: Activity, label: 'Dashboard', end: true },
  { to: '/targets', icon: Target, label: 'Targets' },
  { to: '/scans', icon: Activity, label: 'Scans' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

type ThemeId = 'current' | 'military' | 'futuristic'
const THEMES: { id: ThemeId; label: string }[] = [
  { id: 'current', label: 'Signal' },
  { id: 'military', label: 'Military' },
  { id: 'futuristic', label: 'Futuristic' },
]
const THEME_STORAGE_KEY = 'leadline-theme'

function useTheme() {
  const [theme, setTheme] = useState<ThemeId>(() => {
    const saved = typeof window !== 'undefined' ? window.localStorage.getItem(THEME_STORAGE_KEY) : null
    return (saved as ThemeId) || 'current'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    window.localStorage.setItem(THEME_STORAGE_KEY, theme)
  }, [theme])

  return { theme, setTheme }
}

function App() {
  const { theme, setTheme } = useTheme()
  const [themeMenuOpen, setThemeMenuOpen] = useState(false)

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await fetch('/api/health')
      return res.json()
    },
    refetchInterval: 10000,
  })

  return (
    <div className="min-h-screen bg-void">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-void-800 border-r border-white/5 p-4">
        <div className="flex items-center gap-2 mb-8">
          <Shield className="w-8 h-8 text-signal drop-shadow-[0_0_8px_var(--color-accent-a25)]" />
          <h1 className="text-xl font-bold text-white tracking-tight font-display">Leadline</h1>
        </div>

        <nav className="space-y-1">
          {navItems.map(({ to, icon: Icon, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-2 rounded-md transition-colors ${
                  isActive
                    ? 'bg-signal/10 text-signal border-l-2 border-signal -ml-0.5 pl-[13px]'
                    : 'text-gray-300 hover:bg-white/5 hover:text-white'
                }`
              }
            >
              <Icon className="w-5 h-5" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Theme switcher */}
        <div className="mt-6 relative">
          <button
            onClick={() => setThemeMenuOpen(!themeMenuOpen)}
            className="flex items-center gap-2 px-3 py-2 rounded-md text-gray-300 hover:bg-white/5 hover:text-white transition-colors w-full text-sm"
          >
            <Palette className="w-4 h-4" />
            <span>Theme: {THEMES.find(t => t.id === theme)?.label}</span>
          </button>
          {themeMenuOpen && (
            <div className="mt-1 rounded-md border border-white/10 bg-void-700 overflow-hidden">
              {THEMES.map(t => (
                <button
                  key={t.id}
                  onClick={() => { setTheme(t.id); setThemeMenuOpen(false) }}
                  className={`block w-full text-left px-3 py-2 text-sm transition-colors ${
                    theme === t.id ? 'text-signal bg-signal/10' : 'text-gray-300 hover:bg-white/5'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="absolute bottom-4 left-4 text-xs text-gray-500 flex items-center gap-1.5">
          <span className={`inline-block w-1.5 h-1.5 rounded-full ${health?.status === 'healthy' ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]' : 'bg-rose-500'}`} />
          {health?.status === 'healthy' ? 'Backend Connected' : 'Backend Disconnected'}
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 p-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<TargetsList />} />
          <Route path="/targets/new" element={<TargetForm />} />
          <Route path="/targets/:id" element={<TargetHistory />} />
          <Route path="/targets/:id/edit" element={<TargetForm />} />
          <Route path="/scans" element={<ScansList />} />
          <Route path="/scans/:id" element={<ScanView />} />
          <Route path="/reports" element={<ReportsList />} />
          <Route path="/reports/:id" element={<ReportView />} />
        </Routes>
      </main>
    </div>
  )
}

function Dashboard() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch('/api/targets')
      return res.json()
    },
  })

  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans')
      return res.json()
    },
  })

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Total Targets</h3>
          <p className="text-3xl font-bold">{targets?.length || 0}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Total Scans</h3>
          <p className="text-3xl font-bold">{scans?.length || 0}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Running Scans</h3>
          <p className="text-3xl font-bold text-signal">
            {scans?.filter((s: any) => s.status === 'running').length || 0}
          </p>
        </div>
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
        {scans && scans.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">ID</th>
                <th className="pb-3">Target</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Progress</th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 5).map((scan: any) => (
                <tr key={scan.id} className="border-t border-gray-700">
                  <td className="py-3">#{scan.id}</td>
                  <td className="py-3">
                    <Link to={`/targets/${scan.target_id}`} className="hover:text-signal">
                      {targets?.find((t: any) => t.id === scan.target_id)?.name || `Target #${scan.target_id}`}
                    </Link>
                  </td>
                  <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                  <td className="py-3">
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-signal h-2 rounded-full"
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-500">No scans yet. Create a target and start a scan!</p>
        )}
      </div>
    </div>
  )
}

export default App
