<template>
  <div class="page">
    <h2>📁 SM4 文件加密</h2>
    <p class="page-desc">SM4-CBC（GB/T 32907）| PKCS7 | SM3 密钥派生 1000 轮</p>
    <div class="tool-card">
      <div class="mode-tabs">
        <button :class="{ active: mode === 'encrypt' }" @click="switchMode('encrypt')">🔒 加密</button>
        <button :class="{ active: mode === 'decrypt' }" @click="switchMode('decrypt')">🔓 解密</button>
      </div>

      <div class="drop-zone" @dragover.prevent @drop.prevent="handleDrop" @click="() => fileInput?.click()">
        <div v-if="!file && !files.length">
          <span style="font-size:4rem">{{ mode === 'encrypt' ? '📂' : '📦' }}</span><br/>
          {{ mode === 'encrypt' ? '拖拽文件或文件夹到这里' : '拖拽 .enc 加密文件到这里' }}<br/>
          <span style="font-size:0.8rem;color:var(--text2)">单文件 ≤ {{ fmtSize(MAX) }}，支持多个文件/文件夹批量打包</span>
        </div>
        <div v-else-if="files.length">📦 {{ files.length }} 个文件 ({{ fmtSize(totalSize) }})</div>
        <div v-else>📄 {{ file?.name }} ({{ fmtSize(file?.size) }})</div>
      </div>
      <input ref="fileInput" type="file" hidden @change="handleFile" />
      <input ref="folderInput" type="file" hidden webkitdirectory="true" @change="handleFolder" />
      <input ref="multiInput" type="file" hidden multiple @change="handleFolder" />
      <div style="display:flex;gap:0.5rem;margin-top:0.5rem">
        <button class="btn-sm" v-if="mode === 'encrypt'" @click="() => folderInput?.click()">📁 选文件夹</button>
        <button class="btn-sm" v-if="mode === 'encrypt'" @click="() => multiInput?.click()">📂 多选文件</button>
      </div>
      <div v-if="files.length" class="batch-info">已选 {{ files.length }} 个文件</div>

      <div class="input-group">
        <label>{{ mode === 'encrypt' ? '加密密码' : '解密密码' }}</label>
        <div class="input-row">
          <input v-model="password" :type="showPwd ? 'text' : 'password'" :placeholder="mode === 'encrypt' ? '输入加密密码' : '输入解密密码'" />
          <button class="btn-sm" @click="showPwd = !showPwd">{{ showPwd ? '隐藏' : '显示' }}</button>
          <button class="btn-sm" v-if="mode === 'encrypt'" @click="password = SMC.randomKey(); showPwd = true">🎲 随机生成</button>
          <button class="btn-sm" @click="copy(password)">📋 复制</button>
        </div>
        <div v-if="password" class="key-info">密钥：<code>{{ showPwd ? password : '●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●' }}</code></div>
      </div>

      <button class="btn-primary" @click="process" :disabled="(!file && !files.length) || !password || loading">
        {{ loading ? `⏳ ${progress}` : mode === 'encrypt' ? '🔒 加密' : '🔓 解密' }}
      </button>

      <div v-if="results.length" class="result success">
        <label>处理结果</label>
        <div class="result-box" style="max-height:300px">
          <div v-for="r in results" :key="r.name" style="font-size:0.8rem;margin-bottom:0.2rem">
            {{ r.ok ? '✅' : '❌' }} {{ r.name }} {{ r.hash ? '· '+(typeof r.hash==='string'?r.hash:r.hash) : '· '+r.error }}
          </div>
        </div>
      </div>
      <div v-if="error" class="result error">{{ error }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import SMC from '../utils/smc-sdk.js'
const MAX = SMC.MAX_FILE_SIZE
const mode = ref('encrypt')
const file = ref(null); const files = ref([])
const fileInput = ref(null); const folderInput = ref(null); const multiInput = ref(null)
const password = ref(''); const showPwd = ref(false)
const results = ref([]); const error = ref('')
const loading = ref(false); const progress = ref('')
const totalSize = computed(() => files.value.reduce((s, f) => s + f.size, 0))
function fmtSize(b) { return SMC.fmtSize(b) }
async function copy(text) { await navigator.clipboard.writeText(text) }

onMounted(() => { file.value = null; files.value = []; password.value = ''; results.value = []; error.value = '' })

function switchMode(m) {
  mode.value = m; file.value = null; files.value = []; results.value = []; error.value = ''; password.value = ''
}

function handleFile(e) { file.value = e.target.files[0]; files.value = []; error.value = '' }
function handleDrop(e) {
  const list = Array.from(e.dataTransfer.files).filter(f => f.size > 0)
  if (list.length === 0) return
  if (list[0].webkitRelativePath) { files.value = list; file.value = null }
  else if (list.length === 1) { file.value = list[0]; files.value = [] }
  else { files.value = list; file.value = null }
  error.value = ''
}
function handleFolder(e) {
  const list = Array.from(e.target.files || []).filter(f => f.size > 0 && !f.name.startsWith('.') && !f.name.startsWith('~'))
  if (list.length === 0) { error.value = '所选文件夹中没有有效文件'; return }
  const ts = list.reduce((s, f) => s + f.size, 0)
  if (ts > MAX * 5) { error.value = `总大小 ${fmtSize(ts)} 过大，建议分批处理`; return }
  files.value = list; file.value = null; error.value = ''
}

async function process() {
  error.value = ''; results.value = []
  const isMulti = files.value.length > 0
  loading.value = true

  // 文件模式
  if (isMulti && mode.value === 'encrypt') {
    progress.value = `打包加密 ${files.value.length} 个文件...`
    try {
      const result = await SMC.encryptFolder(files.value, password.value)
      results.value.push({ name: result.root + '.enc', ok: true, hash: result.hash.slice(0, 16) + '...' })
      SMC.downloadFile(await result.blob.arrayBuffer(), result.root + '.enc')
    } catch (e) { results.value.push({ name: '加密失败', ok: false, error: e.message.slice(0, 50) }) }
  } else if (isMulti && mode.value === 'decrypt') {
    for (const f of files.value) {
      if (!f.name.endsWith('.enc')) { results.value.push({ name: f.name, ok: false, error: '不是.enc文件' }); continue }
      try { await decryptOne(f) } catch (e) { results.value.push({ name: f.name, ok: false, error: e.message.slice(0, 50) }) }
    }
  } else {
    const f = file.value
    if (!f) { error.value = '请选择文件'; loading.value = false; return }
    if (f.size === 0) { results.value.push({ name: f.name, ok: false, error: '文件为空' }); loading.value = false; return }
    if (f.size > MAX) { results.value.push({ name: f.name, ok: false, error: '文件过大' }); loading.value = false; return }
    progress.value = '1/1'
    try {
      if (mode.value === 'encrypt') {
        const result = await SMC.encryptFile(f, password.value)
        results.value.push({ name: f.name + '.enc', ok: true, hash: result.hash.slice(0, 16) + '...' })
        SMC.downloadFile(await result.blob.arrayBuffer(), f.name + '.enc')
      } else {
        if (!f.name.endsWith('.enc')) { results.value.push({ name: f.name, ok: false, error: '不是.enc文件' }); loading.value = false; return }
        await decryptOne(f)
      }
    } catch (e) { results.value.push({ name: f.name, ok: false, error: e.message.slice(0, 50) }) }
  }
  loading.value = false; progress.value = ''
}

async function decryptOne(f) {
  const buf = new Uint8Array(await f.arrayBuffer())
  try {
    const dec = await SMC.decryptFolderFromBuffer(buf, password.value, f.name)
    if (dec.count > 1) {
      try {
        const dirHandle = await window.showDirectoryPicker({ mode: 'readwrite' })
        for (const uf of dec.files) {
          const parts = uf.path.split('/'); parts.shift()
          let d = dirHandle
          for (let i = 0; i < parts.length - 1; i++) d = await d.getDirectoryHandle(parts[i], { create: true })
          const fh = await d.getFileHandle(parts[parts.length - 1], { create: true })
          const w = await fh.createWritable(); await w.write(uf.content); await w.close()
        }
        results.value.push({ name: '✅ 已还原到选定目录', ok: true, hash: dec.count + ' 个文件' })
        return
      } catch {}
      for (const uf of dec.files) {
        results.value.push({ name: uf.path, ok: true, hash: '已下载' })
        SMC.downloadFile(uf.content, uf.path.split('/').pop())
        await new Promise(r => setTimeout(r, 200))
      }
      return
    }
  } catch {}
  // 用已读取的 buf，避免重复消耗 File.arrayBuffer()
  const result = await SMC.decryptFileFromBuffer(buf, password.value, f.name)
  results.value.push({ name: result.fileName, ok: result.hashMatch, hash: result.hashMatch ? '完整' : '损坏' })
  SMC.downloadFile(result.fileBytes, result.fileName)
}
</script>
