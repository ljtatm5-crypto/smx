<template>
  <div class="page">
    <h2>✍️ SM2 数据验签</h2>
    <p class="page-desc">SM2 椭圆曲线数字签名（GB/T 32918）。曲线参数：SM2 推荐椭圆曲线 y²=x³+ax+b。签名格式：原始字节 → hex 编码（r,s 各 64 位）。</p>
    <div class="tool-card">
      <!-- 密钥管理 -->
      <div class="input-group">
        <label>SM2 密钥对</label>
        <div class="input-row">
          <button class="btn-sm" @click="genKey">🔑 生成新密钥对</button>
          <button class="btn-sm" @click="exportKey" :disabled="!publicKey">📥 导出密钥</button>
          <button class="btn-sm" @click="saveKey" :disabled="!publicKey">💾 保存到本地</button>
          <button class="btn-sm" @click="loadKey">📂 加载已保存</button>
          <input type="file" ref="keyImport" hidden @change="importKeyFile" accept=".txt" />
          <button class="btn-sm" @click="$refs.keyImport.click()">📤 导入密钥文件</button>
        </div>
        <div v-if="publicKey" class="key-info">
          <div>🔑 公钥（130 hex）：<br/><code style="font-size:0.7rem;word-break:break-all">{{ publicKey }}</code></div>
          <div>🔐 私钥（64 hex）：<br/><code style="font-size:0.7rem;word-break:break-all">{{ privateKey }}</code></div>
        </div>
      </div>

      <hr />

      <div class="mode-tabs">
        <button :class="{ active: mode === 'sign' }" @click="mode = 'sign'">✍️ 签名</button>
        <button :class="{ active: mode === 'verify' }" @click="mode = 'verify'">✅ 验签</button>
      </div>
      <div class="input-group">
        <label>{{ mode === 'sign' ? '待签名数据' : '待验证原文' }}</label>
        <textarea v-model="message" placeholder="输入文本或粘贴文件内容..." rows="3"></textarea>
      </div>
      <div v-if="mode === 'verify'" class="input-group">
        <label>签名 r（64 位 hex）</label><input v-model="sigR" placeholder="r 值" />
        <label style="margin-top:0.5rem">签名 s（64 位 hex）</label><input v-model="sigS" placeholder="s 值" />
        <label style="margin-top:0.5rem">签名者公钥（130 位 hex，04 开头）</label><input v-model="verifyPubKey" placeholder="04..." />
        <div class="input-row" style="margin-top:0.5rem">
          <button class="btn-sm" @click="$refs.sigImport.click()">📤 导入验签包</button>
          <input type="file" ref="sigImport" hidden accept=".json" @change="importSigPack" />
        </div>
      </div>

      <button class="btn-primary" @click="process" :disabled="!message || loading">
        {{ mode === 'sign' ? '✍️ SM2 签名（含时间戳+Nonce 防重放）' : '✅ SM2 验签' }}
      </button>

      <div v-if="signResult" class="result success">
        <label>签名结果（原始字节 hex 编码）</label>
        <div class="result-box">
          <div>⏰ 时间戳（防重放）：{{ signResult.ts }}</div>
          <div>🎲 Nonce（防重放）：{{ signResult.nonce }}</div>
          <div>📝 r（64 hex）：{{ signResult.r }}</div>
          <div>📝 s（64 hex）：{{ signResult.s }}</div>
        </div>
        <button class="btn-sm" @click="exportSigPack">📦 导出验签包（发给对方验证）</button>
      </div>
      <div v-if="verifyResult !== null" class="result" :class="verifyResult ? 'success' : 'error'">
        {{ verifyResult ? '✅ SM2 验签通过 — 数据真实，来源可信，未被篡改' : '❌ SM2 验签失败 — 签名无效、数据被篡改或公钥不匹配' }}
      </div>
      <div v-if="error" class="result error">{{ error }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import SMC from '../utils/smc-sdk.js'

const mode = ref('sign')
const publicKey = ref(''); const privateKey = ref('')
const message = ref(''); const sigR = ref(''); const sigS = ref(''); const verifyPubKey = ref('')
const signResult = ref(null); const verifyResult = ref(null)
const error = ref(''); const loading = ref(false)

onMounted(() => { const kp = SMC.loadKeyPair(); if (kp.publicKey) { publicKey.value = kp.publicKey; privateKey.value = kp.privateKey } })

function genKey() { const kp = SMC.generateKeyPair(); publicKey.value = kp.publicKey; privateKey.value = kp.privateKey }

function exportKey() { SMC.exportKeyPair(publicKey.value, privateKey.value) }
function saveKey() { SMC.saveKeyPair(publicKey.value, privateKey.value); alert('密钥已保存到浏览器本地存储。注意：清除浏览器数据会导致密钥丢失，建议同时导出文件备份。') }
function loadKey() { const kp = SMC.loadKeyPair(); if (!kp.publicKey) { error.value = '未找到本地保存的密钥，请先生成或导入。'; return } publicKey.value = kp.publicKey; privateKey.value = kp.privateKey; error.value = '' }
async function importKeyFile(e) {
  try {
    const text = await e.target.files[0].text()
    const kp = SMC.importKeyPair(text)
    publicKey.value = kp.publicKey; privateKey.value = kp.privateKey; error.value = ''
  } catch (err) { error.value = '密钥文件解析失败：' + err.message }
}

function process() {
  error.value = ''; signResult.value = null; verifyResult.value = null
  try {
    if (mode.value === 'sign') {
      if (!privateKey.value) { error.value = '请先生成或加载 SM2 密钥对。'; return }
      signResult.value = SMC.sign(message.value, privateKey.value, publicKey.value)
    } else {
      verifyResult.value = SMC.verify(message.value, { r: sigR.value.trim(), s: sigS.value.trim() }, verifyPubKey.value.trim())
    }
  } catch (e) { error.value = e.message }
}

async function copy(text) { await navigator.clipboard.writeText(text) }

function exportSigPack() {
  if (!signResult.value) return
  const pack = {
    message: message.value,
    signature: { r: signResult.value.r, s: signResult.value.s },
    publicKey: publicKey.value,
    ts: signResult.value.ts,
    nonce: signResult.value.nonce,
    note: 'SMC SM2 验签包 — 将此文件发给验签方，对方在验签区点「导入验签包」即可自动验证'
  }
  SMC.downloadFile(new TextEncoder().encode(JSON.stringify(pack, null, 2)), 'sm2-sig-pack.json')
}

async function importSigPack(e) {
  try {
    const text = await e.target.files[0].text()
    const pack = JSON.parse(text)
    if (!pack.message || !pack.signature?.r || !pack.publicKey) {
      error.value = '验签包格式无效，缺少必要字段'
      return
    }
    mode.value = 'verify'
    message.value = pack.message
    sigR.value = pack.signature.r
    sigS.value = pack.signature.s
    verifyPubKey.value = pack.publicKey
    error.value = '验签包已加载，请点击「✅ SM2 验签」'
  } catch (err) {
    error.value = '文件解析失败：' + err.message
  }
}
</script>
