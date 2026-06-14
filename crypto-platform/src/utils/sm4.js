// SM4 分组密码算法 (GB/T 32907-2016)
// 128位分组, 128位密钥, 32轮非平衡Feistel网络
// 工作模式: CBC + PKCS7填充

const SBOX = [
  0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
  0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
  0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
  0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
  0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
  0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
  0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
  0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
  0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
  0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
  0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
  0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
  0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
  0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
  0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
  0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
]
const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
const CK = [
  0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
  0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
  0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
  0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
]

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0 }
function sm4Sbox(x) { return SBOX[x&0xff]|(SBOX[(x>>>8)&0xff]<<8)|(SBOX[(x>>>16)&0xff]<<16)|(SBOX[(x>>>24)&0xff]<<24) }
function sm4L(x) { return x^rotl(x,2)^rotl(x,10)^rotl(x,18)^rotl(x,24) }
function sm4Lprime(x) { return x^rotl(x,13)^rotl(x,23) }
function sm4T(x) { return sm4L(sm4Sbox(x)) }
function sm4Tprime(x) { return sm4Lprime(sm4Sbox(x)) }

function expandKey(key) {
  const mk=[],k=[],rk=[]
  for(let i=0;i<4;i++) mk[i]=(key[i*4]<<24)|(key[i*4+1]<<16)|(key[i*4+2]<<8)|key[i*4+3]
  for(let i=0;i<4;i++) k[i]=mk[i]^FK[i]
  for(let i=0;i<32;i++) { rk[i]=k[i]^sm4Tprime(k[i+1]^k[i+2]^k[i+3]^CK[i]); k[i+4]=rk[i] }
  return rk
}

function sm4Round(X, rk) {
  const x=[]
  for(let i=0;i<4;i++) x[i]=(X[i*4]<<24)|(X[i*4+1]<<16)|(X[i*4+2]<<8)|X[i*4+3]
  for(let i=0;i<32;i++) x.push(x[i]^sm4T(x[i+1]^x[i+2]^x[i+3]^rk[i]))
  const out=new Uint8Array(16)
  for(let i=0;i<4;i++) { const v=x[35-i]; out[i*4]=(v>>>24)&0xff; out[i*4+1]=(v>>>16)&0xff; out[i*4+2]=(v>>>8)&0xff; out[i*4+3]=v&0xff }
  return out
}

function sm4Encrypt(block, rk) { return sm4Round(block, rk) }
function sm4Decrypt(block, rk) { return sm4Round(block, [...rk].reverse()) }

function xorBlock(a, b) { const r=new Uint8Array(16); for(let i=0;i<16;i++) r[i]=a[i]^b[i]; return r }

// 安全随机数生成（优先 Web Crypto，file:// 降级到 PRNG）
let _prngState = Date.now() ^ (Math.random() * 0xffffffff)
function _prngNext() {
  _prngState = (_prngState * 1103515245 + 12345) & 0x7fffffff
  return _prngState
}
export function getRandomBytes(n) {
  try {
    return crypto.getRandomValues(new Uint8Array(n))
  } catch {
    const bytes = new Uint8Array(n)
    for (let i = 0; i < n; i++) bytes[i] = _prngNext() & 0xff
    return bytes
  }
}

// === CBC 加密 ===
export function sm4EncryptCBC(plaintext, key) {
  const rk = expandKey(key)
  const iv = getRandomBytes(16)
  const padLen = 16 - (plaintext.length % 16)
  const paddedLen = plaintext.length + padLen
  const padded = new Uint8Array(paddedLen)
  padded.set(plaintext)
  for (let i = plaintext.length; i < paddedLen; i++) padded[i] = padLen
  const blockCount = paddedLen / 16

  const result = new Uint8Array(16 + padded.length) // IV + ciphertext
  result.set(iv)
  let prev = iv
  for (let i = 0; i < blockCount; i++) {
    const block = padded.slice(i * 16, i * 16 + 16)
    const xored = xorBlock(block, prev)
    prev = sm4Encrypt(xored, rk)
    result.set(prev, 16 + i * 16)
  }
  return result
}

// === CBC 解密 ===
export function sm4DecryptCBC(ciphertext, key) {
  if (ciphertext.length < 32) throw new Error('密文格式错误：CBC模式需要 IV(16字节)+至少一个密文块(16字节)')
  const rk = expandKey(key)
  const iv = ciphertext.slice(0, 16)
  const ct = ciphertext.slice(16)
  const blockCount = ct.length / 16
  const result = new Uint8Array(ct.length)
  let prev = iv
  for (let i = 0; i < blockCount; i++) {
    const block = ct.slice(i * 16, i * 16 + 16)
    const decrypted = sm4Decrypt(block, rk)
    result.set(xorBlock(decrypted, prev), i * 16)
    prev = block
  }
  // 去除 PKCS7 填充（全字节一致性校验）
  const padLen = result[result.length - 1]
  if (padLen < 1 || padLen > 16) throw new Error('解密失败：密码错误或文件已损坏（PKCS7填充校验不通过）')
  for (let i = 1; i < padLen; i++) {
    if (result[result.length - 1 - i] !== padLen) throw new Error('解密失败：密码错误或文件已损坏（PKCS7填充不一致）')
  }
  return result.slice(0, result.length - padLen)
}

function hexToBytes(hex) {
  hex = hex.replace(/\s/g, '')
  if (hex.length % 2 !== 0) throw new Error('十六进制格式错误')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// 预查表优化
const T_TABLE = new Uint32Array(256); const TPRIME_TABLE = new Uint32Array(256)
for (let i = 0; i < 256; i++) { T_TABLE[i] = sm4T(i); TPRIME_TABLE[i] = sm4Tprime(i) }

// 密钥缓存池
const keyCache = new Map()
function getCachedRoundKeys(keyHex) {
  if (keyCache.has(keyHex)) { keyCache.get(keyHex).hits++; return keyCache.get(keyHex).rk }
  const key = hexToBytes(keyHex)
  if (key.length !== 16) throw new Error('密钥必须为 16 字节（32 位十六进制）')
  const rk = expandKey(key)
  if (keyCache.size >= 20) keyCache.delete(keyCache.keys().next().value)
  keyCache.set(keyHex, { rk, hits: 0 })
  return rk
}

export function sm4EncryptCBCFromHex(plaintext, keyHex) {
  const encoder = new TextEncoder(); const pt = encoder.encode(plaintext)
  const key = hexToBytes(keyHex)
  return bytesToHex(sm4EncryptCBC(pt, key))
}

export function sm4DecryptCBCToText(cipherHex, keyHex) {
  const ct = hexToBytes(cipherHex); const key = hexToBytes(keyHex)
  const decoder = new TextDecoder()
  return decoder.decode(sm4DecryptCBC(ct, key))
}

export { getCachedRoundKeys, sm4Encrypt, sm4Decrypt, hexToBytes, bytesToHex }
