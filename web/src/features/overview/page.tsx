// SPDX-License-Identifier: GPL-3.0-only
import { Activity, ArrowUpRight, RefreshCw, Radio } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useHealth } from '@/hooks/use-health'

export function OverviewPage() {
  const health = useHealth()
  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <p className="text-sm text-muted-foreground">你的服务器，你的连接</p>
        <h1 className="text-3xl font-semibold tracking-tight">节点概览</h1>
        <p className="max-w-xl text-muted-foreground">在这里查看服务状态，管理自己的代理节点。</p>
      </header>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <Activity className="size-5 text-muted-foreground" aria-hidden="true" />
              <Badge variant={health.status === 'error' ? 'destructive' : 'secondary'}>
                {health.status === 'ready' ? '可访问' : health.status === 'error' ? '连接异常' : '检查中'}
              </Badge>
            </div>
            <CardTitle className="pt-4">管理服务</CardTitle>
            <CardDescription aria-live="polite">{health.message}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" size="sm" onClick={health.refresh} disabled={health.status === 'checking'}>
              <RefreshCw aria-hidden="true" />重新检查
            </Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <Radio className="size-5 text-muted-foreground" aria-hidden="true" />
            <CardTitle className="pt-4">代理监听</CardTitle>
            <CardDescription>当前版本尚未接入代理协议，未启动代理监听。</CardDescription>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">节点配置、凭据和证书管理将在后续版本开放。</CardContent>
        </Card>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-dashed p-5 text-sm">
        <p className="text-muted-foreground">Lunaris 正在开发中。当前页面用于确认管理服务已启动。</p>
        <Link className="inline-flex items-center gap-1 font-medium hover:underline" to="/about">关于项目<ArrowUpRight className="size-4" aria-hidden="true" /></Link>
      </div>
    </div>
  )
}
