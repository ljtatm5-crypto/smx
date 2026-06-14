<template>
  <div class="page">
    <h2>🎮 教学闯关</h2>
    <p class="page-desc">三个关卡从易到难，结合工具箱完成挑战。建议开两个标签页，一个闯关一个工具箱。</p>

    <div class="challenge-menu">
      <router-link to="/challenge/1" class="ch-menu-card">
        <span class="ch-menu-icon">🔓</span>
        <div>
          <h3>第一关：SM4 解密</h3>
          <p>截获密文，还原情报</p>
        </div>
      </router-link>

      <router-link to="/challenge/2" class="ch-menu-card">
        <span class="ch-menu-icon">🔢</span>
        <div>
          <h3>第二关：SM3 哈希</h3>
          <p>哈希匹配，破解密码</p>
        </div>
      </router-link>

      <router-link to="/challenge/3" class="ch-menu-card">
        <span class="ch-menu-icon">🧩</span>
        <div>
          <h3>第三关：综合挑战</h3>
          <p>暴力破解，终极考验</p>
        </div>
      </router-link>
    </div>
  </div>
</template>
