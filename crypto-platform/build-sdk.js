import { readFile, writeFile } from 'fs/promises'

const files = [
  'src/utils/sm4.js',
  'src/utils/sm3.js',
  'src/utils/sm2.js',
  'src/utils/keycache.js',
  'src/utils/audit.js',
  'src/utils/vault.js',
]

let code = '/**\n'
code += ' * 密盾 SMC SDK — 纯 JavaScript 国密算法库\n'
code += ' * 包含: SM2/SM3/SM4 完整实现 + 文件加密 + 审计日志\n'
code += ' * 用法: <script src="smc-sdk.js"></script>\n'
code += ' *        SMC.hash("hello"); // SM3 哈希\n'
code += ' */\n'
code += '(function() {\n"use strict";\n\n'

for (const f of files) {
  let src = await readFile(f, 'utf-8')
  src = src.replace(/^import .*;$/gm, '// [import]')
  src = src.replace(/^export /gm, '')
  code += '\n// === ' + f + ' ===\n' + src + '\n'
}

// Public API
code += `
// === 公共 API ===
window.SMC = {
  // 文件加密
  encryptFile: async function(file, password) {
    const buf = await file.arrayBuffer()
    const saltHex = this.randomKey().slice(0, 16)
    const keyHex = this.deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = encryptFile(new Uint8Array(buf), file.name, keyBytes, hexToBytes(saltHex))
    const h = sm3Hash(new Uint8Array(buf))
    return { blob: new Blob([result.container]), hash: Array.from(h).map(b=>b.toString(16).padStart(2,'0')).join('') }
  },
  decryptFile: async function(file, password) {
    const buf = await file.arrayBuffer()
    const raw = new Uint8Array(buf)
    const salt = extractSalt(raw)
    const saltHex = Array.from(salt).map(b=>b.toString(16).padStart(2,'0')).join('')
    const keyHex = this.deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = decryptFile(raw, keyBytes)
    return { blob: new Blob([result.fileBytes]), fileName: result.fileName, hashMatch: result.hashMatch }
  },
  // SM2
  generateKeyPair: sm2GenerateKeyPair,
  sign: sm2Sign,
  verify: sm2Verify,
  // SM3
  hash: sm3HashHex,
  hmac: sm3HMACHex,
  // 工具
  deriveKeyHex: function(pw, salt) {
    if (/^[0-9a-fA-F]{32}$/.test(pw)) return pw.toLowerCase()
    const k = keyPool.derive(pw, salt || "smc-salt")
    return Array.from(k).map(b=>b.toString(16).padStart(2,'0')).join('')
  },
  randomKey: function() {
    const b = new Uint8Array(16); crypto.getRandomValues(b)
    return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('')
  },
  checkKeyStrength: function(hex) {
    const u = new Set(hex).size
    return u<=4?{level:'弱',color:'#ef4444'}:u<=8?{level:'中',color:'#f59e0b'}:{level:'强',color:'#22c55e'}
  },
  fmtSize: function(b) { return b<1024?b+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(2)+' MB' },
  downloadFile: downloadFile,
  // 密钥管理
  exportKeyPair: function(pub,pri) { downloadFile(new TextEncoder().encode("PUBLIC_KEY="+pub+"\\nPRIVATE_KEY="+pri), "smc-sm2-keypair.txt") },
  loadKeyPair: function() { return { publicKey: localStorage.getItem("smc_sm2_pub")||"", privateKey: localStorage.getItem("smc_sm2_pri")||"" } },
  saveKeyPair: function(pub,pri) { localStorage.setItem("smc_sm2_pub",pub); localStorage.setItem("smc_sm2_pri",pri) },
  // 审计
  getAuditLogs: getAuditLogs,
  verifyLogChain: verifyLogChain,
  exportAuditReport: exportAuditReport,
};
})();
`

await writeFile('public/smc-sdk.js', code, 'utf-8')
console.log('Generated: public/smc-sdk.js (' + code.length + ' chars)')
