<template>
  <div class="page">
    <router-link to="/challenge" class="back-link">← 返回关卡列表</router-link>
    <h2>🔢 第二关：SM3 哈希</h2>
    <p class="page-desc">原文藏在页面某个角落，找到它，用 SM3 工具算哈希来验证。</p>

    <div class="ch-card">
      <div class="ch-data">
        <div><label>SM3 哈希值（验证用）</label><code class="long">{{ target }}</code></div>
      </div>

      <p class="hint">💡 提示：查看页面源代码（F12 → Elements 或 右键→查看源代码），找到原文后去 SM3 工具算哈希，和上面比对，一致就提交。</p>

      <div class="ch-answer">
        <input v-model="answer" placeholder="输入找到的原文..." :disabled="solved" @keyup.enter="check" />
        <button @click="check" :disabled="solved">提交</button>
      </div>
      <div v-if="msg" class="ch-msg" :class="solved ? 'success' : 'fail'">{{ msg }}</div>
    </div>

    <!-- 原文藏在这里 -->
    <!-- secret:flag{古宇航jimaoge} -->
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { sm3HashHex } from '../../utils/sm3.js'

const secret = 'flag{古宇航jimaoge}'
const target = sm3HashHex(secret)
const answer = ref('')
const solved = ref(false)
const msg = ref('')

function check() {
  if (sm3HashHex(answer.value.trim()) === target) {
    solved.value = true
    msg.value = '✅ 正确！你找到了隐藏的原文并验证了 SM3 哈希。'
  } else {
    msg.value = '❌ 哈希不匹配。去页面源代码里找原文，再用 SM3 工具算。'
  }
}
</script>
