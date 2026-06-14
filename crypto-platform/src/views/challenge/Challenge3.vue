<template>
  <div class="page">
    <router-link to="/challenge" class="back-link">← 返回关卡列表</router-link>
    <h2>🧩 第三关：SM2 签名</h2>
    <p class="page-desc">去 SM2 工具箱完成一次数字签名，提交签名结果即可。</p>

    <div class="ch-card">
      <div class="ch-data">
        <div><label>待签名消息</label><code style="font-size:1.1rem;">{{ message }}</code></div>
      </div>
      <p class="hint">
        💡 去 SM2 工具箱 → 生成密钥对 → 输入消息 → 点签名 → 复制 <strong>签名 r 值</strong> 提交。
      </p>

      <div class="ch-answer">
        <input v-model="answer" placeholder="粘贴签名 r 值（64位十六进制）..." :disabled="solved" @keyup.enter="check" />
        <button @click="check" :disabled="solved">提交</button>
      </div>
      <div v-if="msg" class="ch-msg" :class="solved ? 'success' : 'fail'">{{ msg }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const message = 'clxzjy'
const answer = ref('')
const solved = ref(false)
const msg = ref('')

function check() {
  const val = answer.value.trim()
  if (val.length === 64 && /^[0-9a-fA-F]{64}$/.test(val)) {
    solved.value = true
    msg.value = '✅ 格式正确！你已掌握 SM2 数字签名。'
  } else {
    msg.value = '❌ 格式不对。r 值应为 64 位十六进制，检查是否复制完整。'
  }
}
</script>
