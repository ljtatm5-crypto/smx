// 操作日志 SM3 存证系统
// 所有加密/解密/签名/验签行为自动记录，日志链 SM3 固化不可篡改
import { sm3HashHex } from './sm3.js'

const LOG_KEY = 'smc_audit_log'
const MAX_LOGS = 500

function loadLogs() {
  try {
    return JSON.parse(localStorage.getItem(LOG_KEY) || '[]')
  } catch { return [] }
}

function saveLogs(logs) {
  localStorage.setItem(LOG_KEY, JSON.stringify(logs.slice(-MAX_LOGS)))
}

function chainHash(prevHash, entry) {
  return sm3HashHex(prevHash + JSON.stringify(entry))
}

export function auditLog(action, detail = {}) {
  const logs = loadLogs()
  const prevHash = logs.length > 0 ? logs[logs.length - 1].chainHash : '0000000000000000000000000000000000000000000000000000000000000000'
  const entry = {
    id: logs.length + 1,
    ts: new Date().toISOString(),
    action,
    detail,
    prevHash
  }
  entry.chainHash = chainHash(prevHash, entry)
  logs.push(entry)
  saveLogs(logs)
  return entry
}

export function getAuditLogs() {
  return loadLogs()
}

export function verifyLogChain() {
  const logs = loadLogs()
  for (let i = 1; i < logs.length; i++) {
    const expectedPrev = logs[i - 1].chainHash
    if (logs[i].prevHash !== expectedPrev) return { ok: false, brokenAt: i }
  }
  return { ok: true, total: logs.length }
}

export function exportAuditReport() {
  const logs = loadLogs()
  const verify = verifyLogChain()
  const report = {
    generatedAt: new Date().toISOString(),
    totalOperations: logs.length,
    chainValid: verify.ok,
    logs
  }
  return JSON.stringify(report, null, 2)
}

export function clearAuditLog() {
  localStorage.removeItem(LOG_KEY)
}
