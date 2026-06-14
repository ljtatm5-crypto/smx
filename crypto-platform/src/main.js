import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import './assets/main.css'
import { sm3HashHex } from './utils/sm3.js'
import { sm4EncryptCBCFromHex, sm4DecryptCBCToText } from './utils/sm4.js'

window.sm3HashHex = sm3HashHex
window.sm4Encrypt = sm4EncryptCBCFromHex
window.sm4Decrypt = sm4DecryptCBCToText

createApp(App).use(router).mount('#app')
