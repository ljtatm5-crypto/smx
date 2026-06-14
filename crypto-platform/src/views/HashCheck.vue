<template>
  <div class="page">
    <h2>🔍 SM3 哈希校验</h2>
    <p class="page-desc">文本/文件指纹、快照比对、篡改识别。SM3 256 位密码杂凑算法。</p>

    <div class="tool-card">
      <div class="mode-tabs">
        <button :class="{ active: inputType === 'text' }" @click="switchTab('text')">📝 文本</button>
        <button :class="{ active: inputType === 'file' }" @click="switchTab('file')">📁 文件</button>
        <button :class="{ active: inputType === 'compare' }" @click="switchTab('compare')">⚖️ 对比</button>
      </div>

      <div v-if="inputType === 'text'">
        <div class="input-group"><label>输入文本</label><textarea v-model="textInput" rows="3"></textarea></div>
        <button class="btn-primary" @click="hashText">🔢 计算 SM3</button>
      </div>

      <div v-if="inputType === 'file'">
        <div class="drop-zone" @click="fileInput?.click()">
          <div v-if="!fileHash">📂 选择文件计算 SM3 指纹</div>
          <div v-else>📄 {{ fileHash.name }} ({{ fmtSize(fileHash.size) }})</div>
        </div>
        <input ref="fileInput" type="file" hidden @change="handleHashFile" />
        <button class="btn-primary" style="margin-top:1rem" @click="hashFileAction" :disabled="!fileHash">🔢 计算文件 SM3</button>
      </div>

      <div v-if="inputType === 'compare'">
        <div class="input-group"><label>期望哈希值</label><input v-model="expectedHash" placeholder="粘贴期望的 64 位十六进制哈希..." /></div>
        <div class="mode-tabs">
          <button :class="{ active: compareType === 'text' }" @click="compareType = 'text'">📝 文本</button>
          <button :class="{ active: compareType === 'file' }" @click="compareType = 'file'">📁 文件</button>
        </div>
        <div v-if="compareType === 'text'">
          <textarea v-model="compareText" placeholder="输入待校验的文本..." rows="3"></textarea>
        </div>
        <div v-else>
          <div class="drop-zone" @click="fileInput2?.click()">
            <div v-if="!compareFile">📂 选择待校验文件</div>
            <div v-else>📄 {{ compareFile.name }}</div>
          </div>
          <input ref="fileInput2" type="file" hidden @change="e => compareFile = e.target.files[0]" />
        </div>
        <button class="btn-primary" style="margin-top:1rem" @click="compareHash" :disabled="!compareText && !compareFile">⚖️ 对比校验</button>
      </div>

      <div v-if="hashResult" class="result success">
        <label>SM3 哈希值</label>
        <div class="result-box hash">{{ hashResult }}</div>
      </div>
      <div v-if="compareResult !== null" class="result" :class="compareResult ? 'success' : 'error'">
        {{ compareResult ? '✅ 哈希一致 — 文件完整，未被篡改' : '❌ 哈希不一致 — 文件可能被篡改或损坏' }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import SMC from '../utils/smc-sdk.js'

const inputType = ref('text'); const compareType = ref('text')
onMounted(() => resetAll())

function resetAll() {
  textInput.value = ''; expectedHash.value = ''; compareText.value = ''
  hashResult.value = ''; compareResult.value = null
  fileHash.value = null; compareFile.value = null
}

function switchTab(t) {
  inputType.value = t; resetAll()
}
const textInput = ref(''); const expectedHash = ref(''); const compareText = ref('')
const fileHash = ref(null); const compareFile = ref(null)
const hashResult = ref(''); const compareResult = ref(null)

function fmtSize(b) {
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  return (b / 1048576).toFixed(1) + ' MB'
}

function hashText() { hashResult.value = SMC.hash(textInput.value) }
async function handleHashFile(e) { fileHash.value = e.target.files[0] }
async function hashFileAction() {
  const buf = await fileHash.value.arrayBuffer()
  hashResult.value = SMC.hash(new Uint8Array(buf))
}
async function compareHash() {
  let actual
  if (compareType.value === 'text') {
    actual = SMC.hash(compareText.value)
  } else {
    const buf = await compareFile.value.arrayBuffer()
    actual = SMC.hash(new Uint8Array(buf))
  }
  compareResult.value = actual === expectedHash.value.trim().toLowerCase()
  hashResult.value = actual
}
</script>
