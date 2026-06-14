// 密盾 SMC SDK v2 — SM4-CBC + SM3密钥派生 + SM2签名/验签 + 审计日志
import { sm4EncryptCBC, sm4DecryptCBC, hexToBytes, bytesToHex, getRandomBytes } from './sm4.js'
import { sm3Hash, sm3HashHex, sm3HMACHex } from './sm3.js'
import { sm2GenerateKeyPair, sm2Sign, sm2Verify } from './sm2.js'
import { encryptFile, decryptFile, extractSalt, downloadFile, packFolder, unpackFolder } from './vault.js'
import { auditLog, getAuditLogs, verifyLogChain, exportAuditReport } from './audit.js'
import { keyPool } from './keycache.js'

function isHexKey(s) { return /^[0-9a-fA-F]{32}$/.test(s) }

function deriveKeyHex(password, salt = 'smc-salt') {
  // 已是完整的 32 位 hex 密钥 → 直接用，不再派生
  if (isHexKey(password)) return password.toLowerCase()
  const k = keyPool.derive(password, salt)
  return Array.from(k).map(b => b.toString(16).padStart(2, '0')).join('')
}

function randomKey() {
  const b = getRandomBytes(16)
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')
}

function checkKeyStrength(hexKey) {
  const unique = new Set(hexKey).size
  if (unique <= 4) return { level: '弱', color: '#ef4444', tip: '密钥强度极弱，建议重新生成' }
  if (unique <= 8) return { level: '中', color: '#f59e0b', tip: '密钥强度一般' }
  return { level: '强', color: '#22c55e', tip: '密钥强度合格' }
}

function fmtSize(b) {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  return (b / 1048576).toFixed(2) + ' MB'
}

const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024 // 2GB

const SMC = {
  // === 文件加密（SM4-CBC + 盐值绑定）===
  async encryptFile(file, password) {
    if (file.size > MAX_FILE_SIZE) throw new Error(`文件过大（${fmtSize(file.size)}），单文件上限 ${fmtSize(MAX_FILE_SIZE)}，请压缩后重试`)
    const buf = await file.arrayBuffer()
    // 随机盐值 → 写入 .enc 文件明文头部，解密时提取
    const saltHex = randomKey().slice(0, 16) // 8 字节 hex
    const keyHex = deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = encryptFile(new Uint8Array(buf), file.name, keyBytes, hexToBytes(saltHex))
    auditLog('FILE_ENCRYPT', { name: file.name, size: file.size, hash: result.hash.slice(0, 16) })
    return { blob: new Blob([result.container]), hash: result.hash, salt: result.salt, mode: result.mode }
  },

  async decryptFile(file, password) {
    if (file.size > MAX_FILE_SIZE) throw new Error(`文件过大（${fmtSize(file.size)}），单文件上限 ${fmtSize(MAX_FILE_SIZE)}`)
    const buf = await file.arrayBuffer()
    const raw = new Uint8Array(buf)
    // 从文件头提取明文盐值
    const salt = extractSalt(raw)
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    const keyHex = deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = decryptFile(raw, keyBytes)
    auditLog('FILE_DECRYPT', { name: result.fileName, intact: result.hashMatch })
    return { blob: new Blob([result.fileBytes]), fileName: result.fileName, hashMatch: result.hashMatch }
  },

  // 从已读取的 buffer 解密（避免重复调用 File.arrayBuffer()）
  async decryptFileFromBuffer(raw, password, name) {
    const salt = extractSalt(raw)
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    const keyHex = deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = decryptFile(raw, keyBytes)
    auditLog('FILE_DECRYPT', { name: result.fileName, intact: result.hashMatch })
    return { fileBytes: result.fileBytes, fileName: result.fileName, hashMatch: result.hashMatch }
  },

  // === 文件夹打包加密 ===
  async encryptFolder(files, password) {
    const { data, root } = await packFolder(files)
    const saltHex = randomKey().slice(0, 16)
    const keyHex = deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = encryptFile(data, root, keyBytes, hexToBytes(saltHex))
    auditLog('FOLDER_ENCRYPT', { count: files.length, root, hash: result.hash.slice(0, 16) })
    return { blob: new Blob([result.container]), hash: result.hash, root, count: files.length, mode: result.mode }
  },

  async decryptFolder(file, password) {
    if (file.size > MAX_FILE_SIZE) throw new Error('文件过大')
    const buf = await file.arrayBuffer()
    return this.decryptFolderFromBuffer(new Uint8Array(buf), password, file.name)
  },

  async decryptFolderFromBuffer(raw, password, name) {
    const salt = extractSalt(raw)
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    const keyHex = deriveKeyHex(password, saltHex)
    const keyBytes = hexToBytes(keyHex)
    const result = decryptFile(raw, keyBytes)
    if (!result.hashMatch) throw new Error('完整性校验失败，密码错误或文件已损坏')
    const files = unpackFolder(result.fileBytes, result.fileName)
    auditLog('FOLDER_DECRYPT', { root: result.fileName, count: files.length, intact: result.hashMatch })
    return { files, root: result.fileName, count: files.length }
  },

  // === SM2 签名/验签 ===
  generateKeyPair() { auditLog('SM2_KEYGEN', {}); return sm2GenerateKeyPair() },
  sign(message, privateKey, publicKey) {
    const ts = new Date().toISOString(); const nonce = randomKey().slice(0, 16)
    const sig = sm2Sign(message, privateKey, publicKey)
    auditLog('SM2_SIGN', { ts, nonce })
    return { r: sig.r, s: sig.s, ts, nonce }
  },
  verify(message, signature, publicKey) {
    if (!signature.r || !signature.s) throw new Error('签名格式错误：缺少 r 或 s 字段')
    if (signature.r.length !== 64 || signature.s.length !== 64) throw new Error('签名格式错误：r/s 须为 64 位十六进制')
    if (!publicKey.startsWith('04') || publicKey.length !== 130) throw new Error('公钥格式错误：须以 04 开头，共 130 位十六进制')
    const ok = sm2Verify(message, signature, publicKey)
    auditLog('SM2_VERIFY', { result: ok })
    return ok
  },

  // === SM3 哈希 ===
  hash(data) { const h = sm3HashHex(data); auditLog('SM3_HASH', { h16: h.slice(0, 16) }); return h },
  hashBytes: sm3Hash,
  hmac: sm3HMACHex,

  // === 密钥管理 ===
  deriveKeyHex,
  randomKey,
  checkKeyStrength,
  exportKeyPair(publicKey, privateKey) {
    const txt = `# SMC SM2 密钥对\n# 生成时间: ${new Date().toISOString()}\n# 曲线参数: SM2 推荐椭圆曲线 (GB/T 32918)\nPUBLIC_KEY=${publicKey}\nPRIVATE_KEY=${privateKey}`
    downloadFile(new TextEncoder().encode(txt), 'smc-sm2-keypair.txt')
    auditLog('KEY_EXPORT', {})
  },
  importKeyPair(text) {
    const pub = text.match(/PUBLIC_KEY=(\S+)/)
    const pri = text.match(/PRIVATE_KEY=(\S+)/)
    if (!pub || !pri) throw new Error('密钥文件格式错误，缺少 PUBLIC_KEY 或 PRIVATE_KEY')
    return { publicKey: pub[1], privateKey: pri[1] }
  },
  saveKeyPair(publicKey, privateKey) {
    localStorage.setItem('smc_sm2_pub', publicKey)
    localStorage.setItem('smc_sm2_pri', privateKey)
    auditLog('KEY_SAVE', {})
  },
  loadKeyPair() {
    return { publicKey: localStorage.getItem('smc_sm2_pub') || '', privateKey: localStorage.getItem('smc_sm2_pri') || '' }
  },

  // === 审计日志 ===
  getAuditLogs,
  verifyLogChain,
  exportAuditReport,

  // === 工具 ===
  downloadFile, fmtSize, MAX_FILE_SIZE
}

export default SMC
