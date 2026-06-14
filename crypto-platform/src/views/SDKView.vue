<template>
  <div class="page">
    <h2>🔌 开放 API</h2>
    <p class="page-desc">两种接入方式：SDK 直引（前端）和 HTTP 接口（后端/小程序）。</p>

    <!-- SDK 直引 -->
    <div class="guide-section">
      <h3>📦 SDK 直引</h3>
      <div class="guide-card">
        <p>一行 script 标签引入，全部国密能力直接调用。</p>
        <pre class="code-block"><code>&lt;script src="https://ljtatm5-crypto.github.io/smx/smc-sdk.js"&gt;&lt;/script&gt;
&lt;script&gt;
  SMC.hash('hello')                              // SM3 哈希
  SMC.encryptFile(file, 'password')              // SM4 加密
  SMC.generateKeyPair()                          // SM2 密钥对
  SMC.sign('msg', priKey, pubKey)                // SM2 签名
&lt;/script&gt;</code></pre>
        <a :href="sdkUrl" target="_blank" style="color:var(--accent);font-size:0.85rem">📄 查看 SDK 源码</a>
      </div>
    </div>

    <!-- API 接口文档 -->
    <div class="guide-section">
      <h3>🌐 HTTP 接口</h3>
      <div class="guide-card">
        <p>所有接口需在 Header 中携带 <code>Authorization: Bearer sk-xxx</code></p>
        <table class="api-table">
          <tr><th>接口</th><th>参数</th><th>说明</th></tr>
          <tr><td><code>POST /api/sm3/hash</code></td><td>data</td><td>SM3 哈希</td></tr>
          <tr><td><code>POST /api/sm3/hmac</code></td><td>key, data</td><td>SM3 消息认证码</td></tr>
          <tr><td><code>POST /api/sm4/encrypt</code></td><td>plaintext, key</td><td>SM4-CBC 加密</td></tr>
          <tr><td><code>POST /api/sm4/decrypt</code></td><td>ciphertext, key</td><td>SM4-CBC 解密</td></tr>
          <tr><td><code>POST /api/sm2/keygen</code></td><td>—</td><td>生成 SM2 密钥对</td></tr>
          <tr><td><code>POST /api/sm2/sign</code></td><td>message, privateKey, publicKey</td><td>SM2 签名</td></tr>
          <tr><td><code>POST /api/sm2/verify</code></td><td>message, r, s, publicKey</td><td>SM2 验签</td></tr>
        </table>
        <pre class="code-block" style="margin-top:1rem"><code>curl -X POST http://localhost:3456/api/sm3/hash \
  -H "Authorization: Bearer sk-your-key" \
  -H "Content-Type: application/json" \
  -d '{"data":"hello"}'</code></pre>
      </div>
    </div>

    <!-- API Key 管理 -->
    <div class="guide-section">
      <h3>🔑 API 密钥管理</h3>
      <div class="guide-card">
        <p style="font-size:0.85rem;color:#fbbf24;margin-bottom:1rem">
          ⚠️ Key 仅在创建时完整显示一次，请立即复制保存。
        </p>

        <div class="input-row" style="margin-bottom:1rem">
          <input v-model="newName" placeholder="Key 名称（如 atm、my-app）" style="flex:1" />
          <button class="btn-sm" @click="createKey" :disabled="!newName">创建</button>
        </div>
        <div v-if="newKey" class="result success" style="margin-bottom:1rem">
          <label>✅ 新 Key（仅显示一次）</label>
          <div class="result-box">{{ newKey }}</div>
          <button class="btn-sm" @click="copy(newKey)">📋 复制</button>
        </div>
        <div v-if="keyError" class="result error">{{ keyError }}</div>

        <table class="api-table">
          <tr><th>名称</th><th>Key</th><th>创建</th><th>最近使用</th><th>次数</th><th></th></tr>
          <tr v-for="k in keys" :key="k.name">
            <td><strong>{{ k.name }}</strong></td>
            <td><code>{{ k.key }}</code></td>
            <td style="font-size:0.8rem">{{ fmtDate(k.created) }}</td>
            <td style="font-size:0.8rem">{{ k.lastUsed ? fmtDate(k.lastUsed) : '-' }}</td>
            <td>{{ k.usage || 0 }}</td>
            <td><button class="btn-sm" style="color:#ef4444" @click="deleteKey(k.name)">删除</button></td>
          </tr>
        </table>
        <p v-if="keys.length === 0" style="text-align:center;padding:1.5rem;color:var(--text2)">暂无 Key，上方创建一个</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const sdkUrl = import.meta.env.BASE_URL + 'smc-sdk.js'
const API_BASE = localStorage.getItem('smc_api_base') || 'http://localhost:3456'
const apiBase = ref(API_BASE)
const newName = ref(''); const newKey = ref(''); const keyError = ref('')
const keys = ref([])

function fmtDate(d) { return d ? new Date(d).toLocaleString('zh-CN') : '' }
async function loadKeys() {
  try { const r = await fetch(apiBase.value + '/api/keys/list'); keys.value = await r.json() }
  catch { keys.value = [] }
}
async function createKey() {
  keyError.value = ''; newKey.value = ''
  try {
    const r = await fetch(apiBase.value + '/api/keys/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: newName.value }) })
    const d = await r.json(); r.ok ? (newKey.value = d.key, loadKeys()) : keyError.value = d.error
  } catch { keyError.value = '无法连接 API 服务（请先启动 smc-api）' }
}
async function deleteKey(name) { await fetch(apiBase.value + '/api/keys/' + name, { method: 'DELETE' }); loadKeys() }
async function copy(t) { await navigator.clipboard.writeText(t) }
onMounted(loadKeys)
</script>
