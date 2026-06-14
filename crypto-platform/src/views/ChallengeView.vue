<template>
  <div class="page">
    <h2>🎮 教学闯关</h2>
    <p class="page-desc">三个 CTF 式关卡，使用本站文件加密、数据验签、哈希校验工具完成挑战。提示藏在浏览器开发者工具里（F12）。通关后理解国密三件套的核心用法。</p>
    <div class="challenge-list">
      <!-- 关卡1 -->
      <div class="challenge-card" :class="{ solved: c1 }">
        <div class="ch-header"><span class="ch-num">{{ c1 ? '✅' : '1' }}</span><span class="ch-badge">SM4 文件解密</span></div>
        <div class="ch-body">
          <p><strong>任务：</strong>下载下方的加密文件，用 SM4 解密得到 flag。</p>
          <p><strong>知识点：</strong>SM4-CBC 是对称加密算法（GB/T 32907），加密和解密使用同一密钥。</p>
          <div class="ch-data">
            <div><label>🔑 密钥</label><code>0123456789abcdeffedcba9876543210</code></div>
            <div><label>📨 加密文件</label><a :href="encUrl" download class="btn-sm" style="text-decoration:none;display:inline-block">⬇️ 下载 challenge.enc</a></div>
          </div>
          <p class="hint">💡 去 <router-link to="/file">📁 文件加密</router-link> → 切「🔓 解密」→ 拖入下载的 .enc → 输入密钥 → 解密得到 flag → 回来提交</p>
          <div class="ch-answer"><input v-model="a1" placeholder="flag{...}" :disabled="c1" /><button @click="c1 = a1.trim()==='flag{ljtwdblatm}'">提交</button></div>
          <div v-if="c1" class="ch-msg success">✅ SM4 解密通关！对称加密：同密钥加密解密。</div>
        </div>
      </div>
      <!-- 关卡2 -->
      <div class="challenge-card" :class="{ solved: c2 }">
        <div class="ch-header"><span class="ch-num">{{ c2 ? '✅' : '2' }}</span><span class="ch-badge">SM3 哈希寻踪</span></div>
        <div class="ch-body">
          <p><strong>任务：</strong>原文藏在页面源代码的 HTML 注释中（右键→查看源代码，搜索 <code>secret</code>）。找到后用 <router-link to="/hash">🔍 哈希校验</router-link> 算它的 SM3 哈希值，提交哈希值。</p>
          <p><strong>知识点：</strong>SM3 是单向哈希算法，任何数据都有唯一的 SM3 指纹。用哈希工具验证你找到的原文，提交哈希值证明你找到了。</p>
          <div class="ch-answer"><input v-model="a2" placeholder="flag{...}" :disabled="c2" /><button @click="checkL2">提交</button></div>
          <div v-if="c2Msg" class="ch-msg" :class="c2 ? 'success' : 'fail'">{{ c2Msg }}</div>
        </div>
      </div>
      <!-- 关卡3 -->
      <div class="challenge-card" :class="{ solved: c3 }">
        <div class="ch-header"><span class="ch-num">{{ c3 ? '✅' : '3' }}</span><span class="ch-badge">SM2 签名实战</span></div>
        <div class="ch-body">
          <p><strong>任务：</strong>去 <router-link to="/sign">✍️ 数据验签</router-link> 页生成密钥对，对消息 <code>clxzjy</code> 签名，提交签名 r 值的前 16 位。</p>
          <p><strong>知识点：</strong>SM2 是基于椭圆曲线的数字签名算法。私钥签名、公钥验签。签名值 (r,s) 各 64 位 hex，r 是椭圆曲线点的 x 坐标计算结果。</p>
          <div class="ch-answer"><input v-model="a3" placeholder="r值前16位..." :disabled="c3" /><button @click="c3 = a3.trim().length===16 && /^[0-9a-fA-F]+$/.test(a3.trim())">提交</button></div>
          <div v-if="c3" class="ch-msg success">✅ SM2 签名通关！私钥签名，公钥验签——非对称密码的核心。</div>
        </div>
      </div>
    </div>
    <div v-if="c1 && c2 && c3" class="all-done">🎉 全部通关！国产密码 SM2/SM3/SM4 已掌握。</div>
    <div data-secret="flag{SM3哈希校验}" style="display:none"></div>
  </div>
</template>
<script setup>
import { ref, onMounted } from 'vue'
const [c1,c2,c3,a1,a2,a3] = [ref(false),ref(false),ref(false),ref(''),ref(''),ref('')]
onMounted(() => { console.log('🔍 第二关提示：原文藏在 F12 → Elements 里搜 secret，或在源代码中找注释') })
const c2Msg = ref('')
const encUrl = import.meta.env.BASE_URL + 'challenge.enc'
function checkL2() {
  if (a2.value.trim() === 'flag{a1e9aa80b28a98648391b5a615637ba9ddabcb568225c370732311c9542bbf28}') {
    c2.value = true; c2Msg.value = '✅ SM3 哈希正确！原文 → SM3 → flag 格式提交。'
  } else {
    c2Msg.value = '❌ 不对。去 SM3 工具输入找到的原文，把哈希值拼成 flag{哈希} 提交。'
  }
}
</script>
<!-- secret:flag{SM3哈希校验} -->
