<template>
  <div class="page">
    <h2>🎓 国密教学平台</h2>
    <p class="page-desc">国密算法 SM2/SM3/SM4 可视化演示 + CTF 实战闯关</p>

    <div class="mode-tabs" style="margin-bottom:1.5rem">
      <button :class="{ active: tab === 'visual' }" @click="tab = 'visual'">📐 算法可视化</button>
      <button :class="{ active: tab === 'challenge' }" @click="tab = 'challenge'">🎮 实战闯关</button>
    </div>

    <div v-if="tab === 'visual'">
      <Visualize />
    </div>
    <div v-if="tab === 'challenge'">
      <ChallengeView />
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import Visualize from './Visualize.vue'
import ChallengeView from './ChallengeView.vue'

const tab = ref('visual')
</script>
