<template>
  <div class="home">
    <section class="hero">
      <h1>密盾 SMC</h1>
      <p class="subtitle">轻量化 · 可视化 · 免部署 — 国密综合应用平台</p>
      <p class="desc">SM4-CBC 文件加密 | SM2 数字签名验签 | SM3 哈希完整性校验。适配 Windows / 麒麟 / 统信 UOS，开放 API 供二次开发。</p>
      <p style="margin-top:1rem"><router-link to="/guide" class="guide-link">📖 新手指南：每个模块怎么用？点击查看 →</router-link></p>
    </section>

    <section class="modules">
      <router-link to="/file" class="card">
        <span class="card-icon">📁</span><h3>SM4 文件加密</h3>
        <p>拖拽文件 → 设密码 → CBC 加密下载 .enc 文件。支持批量文件夹。</p>
      </router-link>
      <router-link to="/sign" class="card">
        <span class="card-icon">✍️</span><h3>SM2 数据验签</h3>
        <p>密钥生成 → 签名 → 导出验签包。对方导入即验，防伪防篡改。</p>
      </router-link>
      <router-link to="/hash" class="card">
        <span class="card-icon">🔍</span><h3>SM3 哈希校验</h3>
        <p>文本 / 文件指纹 / 期望值对比。文件是否被篡改，一比便知。</p>
      </router-link>
      <router-link to="/visual" class="card">
        <span class="card-icon">📐</span><h3>原理可视化</h3>
        <p>SM4 32轮加密、SM3 压缩函数、SM2 椭圆曲线动画演示。</p>
      </router-link>
      <router-link to="/challenge" class="card">
        <span class="card-icon">🎮</span><h3>教学闯关</h3>
        <p>3 个 CTF 关卡，用本平台工具寻找线索、解密验签。提示藏在 F12 里。</p>
      </router-link>
      <router-link to="/sdk" class="card">
        <span class="card-icon">🔌</span><h3>开放 API</h3>
        <p>smc-sdk.js 纯 JS 零依赖，一行引入。小程序/校园/OA 直接调。</p>
      </router-link>
    </section>
  </div>
</template>
