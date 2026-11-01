// SPDX-License-Identifier: GPL-3.0-only
import { CircleHelp, LayoutDashboard, Moon } from 'lucide-react'
import { BrowserRouter, Link, NavLink, Route, Routes } from 'react-router-dom'
import { OverviewPage } from '@/features/overview/page'
import { AboutPage } from '@/features/about/page'
import { cn } from '@/lib/utils'

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen md:grid md:grid-cols-[220px_1fr]">
        <aside className="flex flex-col border-b bg-sidebar px-5 py-6 md:min-h-screen md:border-r md:border-b-0">
          <Link to="/" className="flex items-center gap-3 px-2 text-xl font-semibold tracking-tight"><Moon className="size-6" aria-hidden="true" />Lunaris</Link>
          <nav aria-label="主导航" className="mt-8 flex gap-2 md:flex-col">
            {[{ to: '/', label: '概览', icon: LayoutDashboard }, { to: '/about', label: '关于', icon: CircleHelp }].map(item => (
              <NavLink key={item.to} to={item.to} end className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring', isActive ? 'bg-accent font-medium text-foreground' : 'text-muted-foreground')}>
                <item.icon className="size-4" aria-hidden="true" />{item.label}
              </NavLink>
            ))}
          </nav>
          <p className="mt-auto hidden px-3 pt-10 text-xs text-muted-foreground md:block">个人节点 · 开发版本</p>
        </aside>
        <main className="mx-auto w-full max-w-6xl px-6 py-10 sm:px-10 lg:px-14 lg:py-14">
          <Routes><Route path="/" element={<OverviewPage />} /><Route path="/about" element={<AboutPage />} /><Route path="*" element={<p>页面不存在。<Link to="/" className="underline">返回概览</Link></p>} /></Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
