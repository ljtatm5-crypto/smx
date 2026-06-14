<template>
  <div class="tool-panel">
    <h3>SM4 加密 / 解密</h3>
    <p class="tool-desc">128 位分组密码，CBC 模式，PKCS7 填充</p>

    <div class="mode-tabs">
      <button :class="{ active: mode === 'encrypt' }" @click="mode = 'encrypt'">🔒 加密</button>
      <button :class="{ active: mode === 'decrypt' }" @click="mode = 'decrypt'">🔓 解密</button>
    </div>

    <div class="input-group">
      <label>密钥（32位十六进制）</label>
      <div class="input-row">
        <input v-model="key" placeholder="0123456789abcdeffedcba9876543210" maxlength="32" />
        <button class="btn-sm" @click="genKey">随机生成</button>
      </div>
    </div>

    <div class="input-group" v-if="mode === 'encrypt'">
      <label>明文</label>
      <textarea v-model="plaintext" placeholder="输入要加密的内容..." rows="3"></textarea>
    </div>

    <div class="input-group" v-if="mode === 'decrypt'">
      <label>密文（十六进制）</label>
      <textarea v-model="ciphertext" placeholder="输入十六进制密文..." rows="3"></textarea>
    </div>

    <button class="btn-primary" @click="process" :disabled="loading">
      {{ loading ? '处理中...' : (mode === 'encrypt' ? '🔒 加密' : '🔓 解密') }}
    </button>

    <div v-if="error" class="result error">{{ error }}</div>
    <div v-if="result" class="result success">
      <label>{{ mode === 'encrypt' ? '密文（Hex）' : '明文' }}</label>
      <div class="result-box">{{ result }}</div>
      <button class="btn-sm" @click="copy(result)">复制</button>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sm4EncryptCBCFromHex, sm4DecryptCBCToText } from '../../utils/sm4.js'

const mode = ref('encrypt')
const key = ref('0123456789abcdeffedcba9876543210')
const plaintext = ref('')
const ciphertext = ref('')
const result = ref('')
const error = ref('')
const loading = ref(false)

function genKey() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  key.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function process() {
  error.value = ''
  result.value = ''
  loading.value = true
  try {
    if (mode.value === 'encrypt') {
      result.value = sm4EncryptCBCFromHex(plaintext.value, key.value)
    } else {
      result.value = sm4DecryptCBCToText(ciphertext.value, key.value)
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
