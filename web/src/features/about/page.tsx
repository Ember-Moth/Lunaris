// SPDX-License-Identifier: GPL-3.0-only
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

export function AboutPage() {
  return (
    <div className="max-w-2xl space-y-8">
      <header className="space-y-2"><h1 className="text-3xl font-semibold tracking-tight">关于 Lunaris</h1><p className="text-muted-foreground">面向个人自用的节点端。</p></header>
      <Card>
        <CardHeader><CardTitle>在自己的服务器上管理连接</CardTitle></CardHeader>
        <CardContent className="space-y-5 text-sm leading-7 text-muted-foreground">
          <p>Lunaris 将节点服务与管理界面一起提供，专注于简单部署、稳定连接和日常维护。</p>
          <p>项目采用 GNU GPL 第 3 版开源协议（GPL-3.0-only）。当前是开发版本，节点核心通过命令行启动，Web 管理功能仍在完善。</p>
          <a className="font-medium text-foreground underline underline-offset-4" href="https://github.com/Ember-Moth/Lunaris">查看项目源码与许可证</a>
        </CardContent>
      </Card>
    </div>
  )
}
