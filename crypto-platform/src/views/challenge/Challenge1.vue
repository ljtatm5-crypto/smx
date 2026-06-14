<template>
  <div class="page">
    <router-link to="/challenge" class="back-link">← 返回关卡列表</router-link>
    <h2>🔓 第一关：SM4 解密</h2>
    <p class="page-desc">截获了用 SM4 加密的密文，已知密钥，还原原文获取 flag。</p>

    <div class="ch-card">
      <div class="ch-data">
        <div><label>密钥</label><code>{{ key }}</code></div>
        <div><label>密文 (Hex)</label><code class="long">{{ cipher }}</code></div>
      </div>
      <p class="hint">💡 去工具箱 SM4 面板 → 解密模式 → 粘贴密钥和密文</p>

      <div class="ch-answer">
        <input v-model="answer" placeholder="输入解密得到的 flag..." :disabled="solved" @keyup.enter="check" />
        <button @click="check" :disabled="solved">提交</button>
      </div>
      <div v-if="msg" class="ch-msg" :class="solved ? 'success' : 'fail'">{{ msg }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sm4EncryptECBHex } from '../../utils/sm4.js'

const key = '0123456789abcdeffedcba9876543210'
const plain = 'FLAG{ljtwdbl奥特曼}'
const cipher = sm4EncryptECBHex(plain, key)

const answer = ref('')
const solved = ref(false)
const msg = ref('')

function check() {
  if (answer.value.trim() === plain) {
    solved.value = true
    msg.value = '✅ 破解成功！'
  } else {
    msg.value = '❌ 不对，检查密钥和密文是否粘贴正确'
  }
}
</script>
