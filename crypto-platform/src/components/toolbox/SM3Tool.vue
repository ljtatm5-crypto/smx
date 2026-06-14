<template>
  <div class="tool-panel">
    <h3>SM3 哈希校验</h3>
    <p class="tool-desc">256 位密码杂凑算法，支持文本和文件输入</p>

    <div class="input-group">
      <label>输入类型</label>
      <div class="mode-tabs">
        <button :class="{ active: inputType === 'text' }" @click="inputType = 'text'">📝 文本</button>
        <button :class="{ active: inputType === 'file' }" @click="inputType = 'file'">📁 文件</button>
        <button :class="{ active: inputType === 'hmac' }" @click="inputType = 'hmac'">🔑 HMAC-SM3</button>
      </div>
    </div>

    <div class="input-group" v-if="inputType === 'text'">
      <label>输入文本</label>
      <textarea v-model="textInput" placeholder="输入要计算哈希的文本..." rows="4"></textarea>
    </div>

    <div class="input-group" v-if="inputType === 'file'">
      <label>选择文件</label>
      <input type="file" @change="handleFile" />
      <div v-if="fileName" class="file-info">已选择: {{ fileName }}</div>
    </div>

    <div class="input-group" v-if="inputType === 'hmac'">
      <label>密钥</label>
      <input v-model="hmacKey" placeholder="HMAC 密钥" />
      <label style="margin-top:10px">消息</label>
      <textarea v-model="hmacMessage" placeholder="输入消息..." rows="3"></textarea>
    </div>

    <button class="btn-primary" @click="compute" :disabled="loading">
      {{ loading ? '计算中...' : '🔢 计算 SM3 哈希' }}
    </button>

    <div v-if="error" class="result error">{{ error }}</div>
    <div v-if="result" class="result success">
      <label>SM3 哈希值（256 bit）</label>
      <div class="result-box hash">{{ result }}</div>
      <button class="btn-sm" @click="copy(result)">复制</button>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sm3HashHex, sm3HashFile, sm3HMACHex } from '../../utils/sm3.js'

const inputType = ref('text')
const textInput = ref('')
const fileName = ref('')
const hmacKey = ref('')
const hmacMessage = ref('')
const result = ref('')
const error = ref('')
const loading = ref(false)
let fileBuffer = null

function handleFile(e) {
  const file = e.target.files[0]
  if (!file) return
  fileName.value = file.name
  const reader = new FileReader()
  reader.onload = () => {
    fileBuffer = reader.result
  }
  reader.readAsArrayBuffer(file)
}

async function compute() {
  error.value = ''
  result.value = ''
  loading.value = true
  try {
    if (inputType.value === 'text') {
      result.value = sm3HashHex(textInput.value)
    } else if (inputType.value === 'file') {
      if (!fileBuffer) throw new Error('请选择文件')
      result.value = sm3HashHex(sm3HashFile(fileBuffer))
    } else {
      result.value = sm3HMACHex(hmacKey.value, hmacMessage.value)
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
