import express from 'express'
import cors from 'cors'
import { readFileSync, writeFileSync, existsSync } from 'fs'

// 算法核心（从 crypto-platform 项目引用）
import { sm3HashHex, sm3HMACHex } from '../crypto-platform/src/utils/sm3.js'
import { sm2GenerateKeyPair, sm2Sign, sm2Verify } from '../crypto-platform/src/utils/sm2.js'
import { sm4EncryptCBCFromHex, sm4DecryptCBCToText } from '../crypto-platform/src/utils/sm4.js'

const KEYS_FILE = './api-keys.json'

// 加载/保存 API keys
function loadKeys() {
  if (!existsSync(KEYS_FILE)) return []
  return JSON.parse(readFileSync(KEYS_FILE, 'utf-8'))
}
function saveKeys(keys) { writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2)) }

// 生成 key: sk-随机32位hex
function genKey() {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return 'sk-' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// API key 鉴权中间件
function auth(req, res, next) {
  const key = req.headers['authorization']?.replace('Bearer ', '') || req.query.api_key
  if (!key) return res.status(401).json({ error: '缺少 API key，请在 Authorization 头传入 Bearer sk-xxx' })
  const keys = loadKeys()
  const found = keys.find(k => k.key === key)
  if (!found) return res.status(403).json({ error: 'API key 无效' })
  found.lastUsed = new Date().toISOString()
  if (found.usage) found.usage++
  else found.usage = 1
  saveKeys(keys)
  req.apiKey = found
  next()
}

const app = express()
app.use(cors())
app.use(express.json({ limit: '50mb' }))

// === Key 管理 ===
app.post('/api/keys/create', (req, res) => {
  const { name } = req.body
  if (!name) return res.status(400).json({ error: '缺少 name' })
  const keys = loadKeys()
  if (keys.find(k => k.name === name)) return res.status(400).json({ error: '名称已存在' })
  const newKey = { name, key: genKey(), created: new Date().toISOString(), usage: 0 }
  keys.push(newKey)
  saveKeys(keys)
  res.json({ name: newKey.name, key: newKey.key, created: newKey.created, usage: 0 })
})

app.get('/api/keys/list', (req, res) => {
  // 返回列表但隐藏完整 key
  const keys = loadKeys().map(k => ({
    name: k.name,
    key: k.key.slice(0, 7) + '************************' + k.key.slice(-4),
    created: k.created,
    lastUsed: k.lastUsed,
    usage: k.usage
  }))
  res.json(keys)
})

app.delete('/api/keys/:name', (req, res) => {
  let keys = loadKeys()
  keys = keys.filter(k => k.name !== req.params.name)
  saveKeys(keys)
  res.json({ ok: true })
})

// === 受保护的 API 接口 ===
app.post('/api/sm3/hash', auth, (req, res) => {
  const { data } = req.body
  if (!data) return res.status(400).json({ error: '缺少 data' })
  res.json({ hash: sm3HashHex(data) })
})

app.post('/api/sm3/hmac', auth, (req, res) => {
  const { key, data } = req.body
  res.json({ hmac: sm3HMACHex(key, data) })
})

app.post('/api/sm2/keygen', auth, (req, res) => {
  res.json(sm2GenerateKeyPair())
})

app.post('/api/sm2/sign', auth, (req, res) => {
  const { message, privateKey, publicKey } = req.body
  try {
    res.json(sm2Sign(message, privateKey, publicKey))
  } catch (e) { res.status(400).json({ error: e.message }) }
})

app.post('/api/sm2/verify', auth, (req, res) => {
  const { message, r, s, publicKey } = req.body
  try {
    res.json({ valid: sm2Verify(message, { r, s }, publicKey) })
  } catch (e) { res.status(400).json({ error: e.message }) }
})

app.post('/api/sm4/encrypt', auth, (req, res) => {
  const { plaintext, key } = req.body
  try { res.json({ ciphertext: sm4EncryptCBCFromHex(plaintext, key) }) }
  catch (e) { res.status(400).json({ error: e.message }) }
})

app.post('/api/sm4/decrypt', auth, (req, res) => {
  const { ciphertext, key } = req.body
  try { res.json({ plaintext: sm4DecryptCBCToText(ciphertext, key) }) }
  catch (e) { res.status(400).json({ error: e.message }) }
})

// 健康检查（无需鉴权）
app.get('/api/health', (req, res) => res.json({ status: 'ok' }))

const PORT = process.env.PORT || 3456
app.listen(PORT, () => console.log(`SMC API → http://localhost:${PORT}`))
