<template>
  <div class="page">
    <h2>📋 操作日志存证</h2>
    <p class="page-desc">全流程 SM3 链式存证。每条日志包含上一条 SM3 指纹，形成不可篡改的哈希链，满足合规审计溯源要求。</p>
    <div class="tool-card">
      <div class="input-row" style="margin-bottom:1rem">
        <button class="btn-sm" @click="refresh">🔄 刷新</button>
        <button class="btn-sm" @click="verify">🔍 校验链完整性</button>
        <button class="btn-sm" @click="exportReport">📥 导出审计报告</button>
        <button class="btn-sm" @click="clear" style="color:#ef4444">🗑️ 清空日志</button>
      </div>
      <div v-if="chainStatus !== null" class="result" :class="chainStatus ? 'success' : 'error'">
        {{ chainStatus ? '✅ SM3 哈希链完整 — 日志未被篡改' : '❌ 哈希链断裂 — 日志可能被篡改！' }}
      </div>
      <div v-if="logs.length === 0" style="text-align:center;padding:2rem;color:var(--text2)">暂无操作日志。执行加密/签名/哈希操作后自动生成。</div>
      <div v-for="log in logs.slice().reverse()" :key="log.id" class="log-entry">
        <div class="log-header">
          <span class="log-id">#{{ log.id }}</span>
          <span class="log-action">{{ log.action }}</span>
          <span class="log-ts">{{ log.ts }}</span>
        </div>
        <div class="log-hash">SM3：{{ log.chainHash.slice(0, 32) }}...</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import SMC from '../utils/smc-sdk.js'

const logs = ref([])
const chainStatus = ref(null)

function refresh() { logs.value = SMC.getAuditLogs(); chainStatus.value = null }
function verify() { const r = SMC.verifyLogChain(); chainStatus.value = r.ok; logs.value = SMC.getAuditLogs() }
function exportReport() { const json = SMC.exportAuditReport(); SMC.downloadFile(new TextEncoder().encode(json), 'smc-audit-report.json'); refresh() }
function clear() { if (confirm('确定清空所有操作日志？此操作不可恢复。')) { localStorage.removeItem('smc_audit_log'); refresh() } }
refresh()
</script>
