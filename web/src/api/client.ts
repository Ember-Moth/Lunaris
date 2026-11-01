// SPDX-License-Identifier: GPL-3.0-only
import type { paths } from './schema'

type Health = paths['/healthz']['get']['responses'][200]['content']['application/json']['data']

export async function getHealth(signal: AbortSignal): Promise<Health> {
  const response = await fetch('/healthz', { signal, cache: 'no-store' })
  if (!response.ok) throw new Error('暂时无法连接管理服务，请检查服务是否运行。')
  const body: unknown = await response.json()
  if (!body || typeof body !== 'object' || !('code' in body) || body.code !== 0 || !('data' in body) ||
    !body.data || typeof body.data !== 'object' || !('status' in body.data) || body.data.status !== 'ok') {
    throw new Error('管理服务返回了无法识别的状态。')
  }
  return { status: 'ok' }
}
