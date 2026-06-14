<template>
  <div class="tool-panel">
    <h3>SM2 签名 / 验签</h3>
    <p class="tool-desc">椭圆曲线数字签名算法，256 位安全强度</p>

    <div class="input-group">
      <label>密钥对</label>
      <div class="input-row">
        <button class="btn-sm" @click="genKeyPair" :disabled="loading">生成新密钥对</button>
      </div>
      <div v-if="publicKey" class="key-info">
        <div><strong>公钥 (130 hex):</strong></div>
        <div class="key-text">{{ publicKey.slice(0, 40) }}...</div>
        <div><strong>私钥 (64 hex):</strong></div>
        <div class="key-text">{{ privateKey.slice(0, 32) }}...</div>
      </div>
    </div>

    <hr />

    <div class="mode-tabs">
      <button :class="{ active: mode === 'sign' }" @click="mode = 'sign'">✍️ 签名</button>
      <button :class="{ active: mode === 'verify' }" @click="mode = 'verify'">✅ 验签</button>
    </div>

    <div class="input-group">
      <label>消息</label>
      <textarea v-model="message" placeholder="输入要签名的消息..." rows="3"></textarea>
    </div>

    <div v-if="mode === 'verify'" class="input-group">
      <label>签名 r (64 hex)</label>
      <input v-model="sigR" placeholder="r 值" />
      <label style="margin-top:10px">签名 s (64 hex)</label>
      <input v-model="sigS" placeholder="s 值" />
    </div>

    <button class="btn-primary" @click="process" :disabled="loading || !privateKey">
      {{ loading ? '处理中...' : (mode === 'sign' ? '✍️ 签名' : '✅ 验证签名') }}
    </button>

    <div v-if="error" class="result error">{{ error }}</div>
    <div v-if="signResult" class="result success">
      <label>签名结果</label>
      <div class="result-box">
        <div><strong>r:</strong> {{ signResult.r }}</div>
        <div><strong>s:</strong> {{ signResult.s }}</div>
      </div>
      <button class="btn-sm" @click="copy(signResult.r + signResult.s)">复制签名</button>
    </div>
    <div v-if="verifyResult !== null" class="result" :class="verifyResult ? 'success' : 'error'">
      {{ verifyResult ? '✅ 签名验证通过' : '❌ 签名验证失败' }}
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sm2GenerateKeyPair, sm2Sign, sm2Verify } from '../../utils/sm2.js'

const mode = ref('sign')
const publicKey = ref('')
const privateKey = ref('')
const message = ref('')
const sigR = ref('')
const sigS = ref('')
const signResult = ref(null)
const verifyResult = ref(null)
const error = ref('')
const loading = ref(false)

async function genKeyPair() {
  loading.value = true
  const kp = sm2GenerateKeyPair()
  publicKey.value = kp.publicKey
  privateKey.value = kp.privateKey
  error.value = ''
  loading.value = false
}

async function process() {
  error.value = ''
  signResult.value = null
  verifyResult.value = null
  loading.value = true
  try {
    if (mode.value === 'sign') {
      const sig = sm2Sign(message.value, privateKey.value, publicKey.value)
      signResult.value = sig
    } else {
      verifyResult.value = sm2Verify(message.value, { r: sigR.value, s: sigS.value }, publicKey.value)
    }
  } catch (e) {
    error.value = e.message
  }
  loading.value = false
}

async function copy(text) {
  await navigator.clipboard.writeText(text)
}
</script>
