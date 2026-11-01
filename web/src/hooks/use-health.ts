// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useState } from 'react'
import { getHealth } from '@/api/client'

type HealthState = { status: 'checking' | 'ready' | 'error'; message: string }

export function useHealth() {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<HealthState>({ status: 'checking', message: '正在检查管理服务…' })

  useEffect(() => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(new Error('连接超时，请稍后重试。')), 5000)
    getHealth(controller.signal)
      .then(() => setState({ status: 'ready', message: '管理服务与本地存储可访问。' }))
      .catch((error: unknown) => {
        if (controller.signal.aborted && controller.signal.reason === 'unmounted') return
        setState({ status: 'error', message: error instanceof Error ? error.message : '暂时无法获取运行状态。' })
      })
      .finally(() => clearTimeout(timeout))
    return () => { controller.abort('unmounted'); clearTimeout(timeout) }
  }, [attempt])

  const refresh = () => {
    setState({ status: 'checking', message: '正在检查管理服务…' })
    setAttempt(value => value + 1)
  }
  return { ...state, refresh }
}
