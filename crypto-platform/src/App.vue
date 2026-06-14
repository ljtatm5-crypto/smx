<template>
  <div class="app">
    <nav class="navbar">
      <router-link to="/" class="logo">国密算法综合应用平台</router-link>
      <div class="nav-links">
        <router-link to="/file">📁 文件加密</router-link>
        <router-link to="/sign">✍️ 数据验签</router-link>
        <router-link to="/hash">🔍 哈希校验</router-link>
        <router-link to="/visual">📐 可视化</router-link>
        <router-link to="/challenge">🎮 闯关</router-link>
        <router-link to="/sdk">🔌 API</router-link>
        <router-link to="/audit">📋 日志</router-link>
      </div>
    </nav>
    <main class="main-content"><router-view /></main>
  </div>
</template>
