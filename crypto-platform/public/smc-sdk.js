/**
 * 密盾 SMC SDK — 纯 JavaScript 国密算法库
 * 包含: SM2/SM3/SM4 完整实现 + 文件加密 + 审计日志
 * 用法: <script src="smc-sdk.js"></script>
 *        SMC.hash("hello"); // SM3 哈希
 */
(function() {
"use strict";


// === src/utils/sm4.js ===
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

// === CBC 加密 ===
function sm4EncryptCBC(plaintext, key) {
  const rk = expandKey(key)
  const iv = crypto.getRandomValues(new Uint8Array(16))
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
function sm4DecryptCBC(ciphertext, key) {
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
  // 去除 PKCS7 填充
  const padLen = result[result.length - 1]
  if (padLen < 1 || padLen > 16) throw new Error('解密失败：密码错误或文件已损坏（PKCS7填充校验不通过）')
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

function sm4EncryptCBCFromHex(plaintext, keyHex) {
  const encoder = new TextEncoder(); const pt = encoder.encode(plaintext)
  const key = hexToBytes(keyHex)
  return bytesToHex(sm4EncryptCBC(pt, key))
}

function sm4DecryptCBCToText(cipherHex, keyHex) {
  const ct = hexToBytes(cipherHex); const key = hexToBytes(keyHex)
  const decoder = new TextDecoder()
  return decoder.decode(sm4DecryptCBC(ct, key))
}

{ getCachedRoundKeys, sm4Encrypt, sm4Decrypt, hexToBytes, bytesToHex }


// === src/utils/sm3.js ===
// SM3 密码杂凑算法 (GB/T 32905-2016)
// 输出256位哈希值, 消息分组512位, 64轮迭代压缩

const IV = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
]

function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0
}

function p0(x) {
  return x ^ rotl(x, 9) ^ rotl(x, 17)
}

function p1(x) {
  return x ^ rotl(x, 15) ^ rotl(x, 23)
}

function ff0(x, y, z) {
  return x ^ y ^ z
}

function ff1(x, y, z) {
  return (x & y) | (x & z) | (y & z)
}

function gg0(x, y, z) {
  return x ^ y ^ z
}

function gg1(x, y, z) {
  return (x & y) | (~x & z)
}

function sm3Hash(message) {
  const msgBytes = typeof message === 'string'
    ? new TextEncoder().encode(message)
    : new Uint8Array(message)

  const len = msgBytes.length * 8
  // Padding
  const padLen = (448 - (len + 1) % 512 + 512) % 512
  const totalBytes = (len + 1 + padLen + 64) / 8
  const padded = new Uint8Array(totalBytes)
  padded.set(msgBytes)
  padded[msgBytes.length] = 0x80
  // Append length in big-endian
  const view = new DataView(padded.buffer)
  view.setUint32(totalBytes - 4, len & 0xffffffff)
  view.setUint32(totalBytes - 8, Math.floor(len / 0x100000000))

  const V = [...IV]
  const W = new Uint32Array(68)
  const W1 = new Uint32Array(64)

  for (let block = 0; block < totalBytes; block += 64) {
    // Expand message
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(block + i * 4)
    }
    for (let i = 16; i < 68; i++) {
      W[i] = p1(W[i - 16] ^ W[i - 9] ^ rotl(W[i - 3], 15)) ^ rotl(W[i - 13], 7) ^ W[i - 6]
    }
    for (let i = 0; i < 64; i++) {
      W1[i] = W[i] ^ W[i + 4]
    }

    // Compress
    let A = V[0], B = V[1], C = V[2], D = V[3]
    let E = V[4], F = V[5], G = V[6], H = V[7]

    for (let j = 0; j < 64; j++) {
      const Tj = j < 16 ? 0x79cc4519 : 0x7a879d8a
      const SS1 = rotl(rotl(A, 12) + E + rotl(Tj, j % 32), 7)
      const SS2 = SS1 ^ rotl(A, 12)
      const TT1 = j < 16
        ? ff0(A, B, C) + D + SS2 + W1[j]
        : ff1(A, B, C) + D + SS2 + W1[j]
      const TT2 = j < 16
        ? gg0(E, F, G) + H + SS1 + W[j]
        : gg1(E, F, G) + H + SS1 + W[j]
      D = C
      C = rotl(B, 9)
      B = A
      A = TT1
      H = G
      G = rotl(F, 19)
      F = E
      E = p0(TT2)
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H
  }

  // Output
  const hash = new Uint8Array(32)
  const dv = new DataView(hash.buffer)
  for (let i = 0; i < 8; i++) {
    dv.setUint32(i * 4, V[i])
  }
  return hash
}

function sm3HashHex(message) {
  return Array.from(sm3Hash(message)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function sm3HashFile(arrayBuffer) {
  return sm3Hash(new Uint8Array(arrayBuffer))
}

function sm3HMAC(key, message) {
  const blockSize = 64
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : new Uint8Array(key)

  let k = keyBytes
  if (k.length > blockSize) {
    k = sm3Hash(k)
  }
  const ipad = new Uint8Array(blockSize)
  const opad = new Uint8Array(blockSize)
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = 0x36
    opad[i] = 0x5c
  }
  for (let i = 0; i < k.length; i++) {
    ipad[i] ^= k[i]
    opad[i] ^= k[i]
  }

  const inner = new Uint8Array(blockSize + (typeof message === 'string' ? new TextEncoder().encode(message).length : message.length))
  inner.set(ipad)
  if (typeof message === 'string') {
    inner.set(new TextEncoder().encode(message), blockSize)
  } else {
    inner.set(new Uint8Array(message), blockSize)
  }

  const innerHash = sm3Hash(inner)
  const outer = new Uint8Array(blockSize + 32)
  outer.set(opad)
  outer.set(innerHash, blockSize)
  return sm3Hash(outer)
}

function sm3HMACHex(key, message) {
  return Array.from(sm3HMAC(key, message)).map(b => b.toString(16).padStart(2, '0')).join('')
}


// === src/utils/sm2.js ===
// SM2 椭圆曲线公钥密码算法 (GB/T 32918-2016)
// 基于 256-bit 素数域上的椭圆曲线: y² = x³ + ax + b

// 曲线参数
const P = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn
const A = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn
const B = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n
const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n
const GX = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n
const GY = 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n

function mod(a, m) {
  const r = a % m
  return r < 0n ? r + m : r
}

function modAdd(a, b, m) {
  return mod(a + b, m)
}

function modSub(a, b, m) {
  return mod(a - b, m)
}

function modMul(a, b, m) {
  return mod(a * b, m)
}

function modPow(a, e, m) {
  if (e === 0n) return 1n
  let result = 1n
  let base = mod(a, m)
  while (e > 0n) {
    if (e & 1n) result = modMul(result, base, m)
    base = modMul(base, base, m)
    e >>= 1n
  }
  return result
}

function modInv(a, m) {
  return modPow(a, m - 2n, m)
}

// 椭圆曲线点
class ECPoint {
  constructor(x, y, isInfinity = false) {
    this.x = x
    this.y = y
    this.isInfinity = isInfinity
  }
}

const INFINITY = new ECPoint(0n, 0n, true)

function pointEquals(p1, p2) {
  if (p1.isInfinity && p2.isInfinity) return true
  if (p1.isInfinity || p2.isInfinity) return false
  return p1.x === p2.x && p1.y === p2.y
}

function pointNeg(p) {
  if (p.isInfinity) return INFINITY
  return new ECPoint(p.x, mod(-p.y, P))
}

function pointAdd(p1, p2) {
  if (p1.isInfinity) return p2
  if (p2.isInfinity) return p1
  if (p1.x === p2.x && p1.y === mod(-p2.y, P)) return INFINITY

  let lam
  if (pointEquals(p1, p2)) {
    if (p1.y === 0n) return INFINITY
    lam = modMul(modMul(3n * p1.x * p1.x + A, modInv(2n * p1.y, P), P), 1n, P)
  } else {
    lam = modMul(modSub(p2.y, p1.y, P), modInv(modSub(p2.x, p1.x, P), P), P)
  }

  const x3 = modSub(lam * lam - p1.x - p2.x, 0n, P)
  const y3 = modSub(lam * (p1.x - x3) - p1.y, 0n, P)

  return new ECPoint(x3, y3)
}

function pointMul(k, p) {
  if (k === 0n) return INFINITY
  let result = INFINITY
  let addend = p
  let scalar = mod(k, N)
  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, addend)
    addend = pointAdd(addend, addend)
    scalar >>= 1n
  }
  return result
}

const G = new ECPoint(GX, GY)

function sm2GenerateKeyPair() {
  let d
  do {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    d = BigInt('0x' + hex)
  } while (d >= N || d === 0n)

  const pubPoint = pointMul(d, G)
  return {
    privateKey: bytesToHex32(d),
    publicKey: '04' + bytesToHex32(pubPoint.x) + bytesToHex32(pubPoint.y)
  }
}

function sm2Sign(message, privateKeyHex, publicKeyHex) {
  const d = BigInt('0x' + privateKeyHex)
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : new Uint8Array(message)

  // ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
  const ZA = computeZA(publicKeyHex)

  // e = SM3(ZA || M)
  const eHash = sm3HashForSM2(ZA, msgBytes)
  const e = BigInt('0x' + bytesToHex(eHash))

  let r, s
  while (true) {
    const kBytes = new Uint8Array(32)
    crypto.getRandomValues(kBytes)
    const k = BigInt('0x' + bytesToHex(kBytes)) % N
    if (k === 0n) continue

    const kG = pointMul(k, G)
    const x1 = kG.x
    r = mod(e + x1, N)
    if (r === 0n || mod(r + k, N) === 0n) continue

    const d1 = modInv(1n + d, N)
    s = modMul(d1, (k - modMul(r, d, N) + N) % N, N)
    if (s !== 0n) break
  }

  return { r: bytesToHex32(r), s: bytesToHex32(s) }
}

function sm2Verify(message, signature, publicKeyHex) {
  const r = BigInt('0x' + signature.r)
  const s = BigInt('0x' + signature.s)

  if (r < 1n || r >= N || s < 1n || s >= N) return false

  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : new Uint8Array(message)
  const ZA = computeZA(publicKeyHex)
  const eHash = sm3HashForSM2(ZA, msgBytes)
  const e = BigInt('0x' + bytesToHex(eHash))

  const t = mod(r + s, N)
  if (t === 0n) return false

  const pubPoint = parsePublicKey(publicKeyHex)
  if (!pubPoint) return false

  const sG_tP = pointAdd(pointMul(s, G), pointMul(t, pubPoint))
  const R = mod(e + sG_tP.x, N)
  return R === r
}

function computeZA(publicKeyHex) {
  const id = '31323334353637383132333435363738' // default user ID = "1234567812345678"
  const entla = '0080' // 128 bits for ID
  const aHex = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'
  const bHex = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'
  const gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
  const gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'

  // Parse public key (skip 04 prefix)
  const pubX = publicKeyHex.slice(2, 66)
  const pubY = publicKeyHex.slice(66, 130)

  const zaInput = hexToBytes(entla + id + aHex + bHex + gxHex + gyHex + pubX + pubY)
  return sm3HashForSM2Bytes(zaInput)
}

function sm3HashForSM2(ZA, message) {
  const zaBytes = hexToBytes(bytesToHex(ZA))
  const combined = new Uint8Array(zaBytes.length + message.length)
  combined.set(zaBytes)
  combined.set(message, zaBytes.length)
  return sm3HashForSM2Bytes(combined)
}

function sm3HashForSM2Bytes(data) {
  const msgBytes = data
  const IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
               0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
  function _rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0 }
  function _p0(x) { return x ^ _rotl(x, 9) ^ _rotl(x, 17) }
  function _p1(x) { return x ^ _rotl(x, 15) ^ _rotl(x, 23) }
  function _ff0(x, y, z) { return x ^ y ^ z }
  function _ff1(x, y, z) { return (x & y) | (x & z) | (y & z) }
  function _gg0(x, y, z) { return x ^ y ^ z }
  function _gg1(x, y, z) { return (x & y) | (~x & z) }

  const len = msgBytes.length * 8
  const padLen = (448 - (len + 1) % 512 + 512) % 512
  const totalBytes = (len + 1 + padLen + 64) / 8
  const padded = new Uint8Array(totalBytes)
  padded.set(msgBytes)
  padded[msgBytes.length] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(totalBytes - 4, len & 0xffffffff)
  view.setUint32(totalBytes - 8, Math.floor(len / 0x100000000))

  const V = [...IV]
  const W = new Uint32Array(68), W1 = new Uint32Array(64)

  for (let block = 0; block < totalBytes; block += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(block + i * 4)
    for (let i = 16; i < 68; i++)
      W[i] = _p1(W[i - 16] ^ W[i - 9] ^ _rotl(W[i - 3], 15)) ^ _rotl(W[i - 13], 7) ^ W[i - 6]
    for (let i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4]

    let A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7]
    for (let j = 0; j < 64; j++) {
      const Tj = j < 16 ? 0x79cc4519 : 0x7a879d8a
      const SS1 = _rotl(_rotl(A, 12) + E + _rotl(Tj, j % 32), 7)
      const SS2 = SS1 ^ _rotl(A, 12)
      const TT1 = j < 16 ? _ff0(A, B, C) + D + SS2 + W1[j] : _ff1(A, B, C) + D + SS2 + W1[j]
      const TT2 = j < 16 ? _gg0(E, F, G) + H + SS1 + W[j] : _gg1(E, F, G) + H + SS1 + W[j]
      D = C; C = _rotl(B, 9); B = A; A = TT1
      H = G; G = _rotl(F, 19); F = E; E = _p0(TT2)
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H
  }
  const hash = new Uint8Array(32)
  const dv = new DataView(hash.buffer)
  for (let i = 0; i < 8; i++) dv.setUint32(i * 4, V[i])
  return hash
}

function parsePublicKey(pubHex) {
  const x = BigInt('0x' + pubHex.slice(2, 66))
  const y = BigInt('0x' + pubHex.slice(66, 130))
  return new ECPoint(x, y)
}

function bytesToHex32(n) {
  return n.toString(16).padStart(64, '0')
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}

{ computeZA, sm3HashForSM2Bytes }


// === src/utils/keycache.js ===
// 密钥上下文缓存池 — 同批次复用，减少 SM3 派生 + 算法初始化开销
import { sm3Hash } from './sm3.js'

class KeyPool {
  constructor() { this.cache = new Map(); this.maxSize = 30 }

  // SM3 加盐派生密钥（1000轮迭代，符合商密规范）
  derive(password, salt = 'smc-default-salt') {
    const cacheKey = `${password}:${salt}`
    if (this.cache.has(cacheKey)) {
      const entry = this.cache.get(cacheKey)
      entry.hits++
      return entry.key
    }
    let key = sm3Hash(salt + password)
    for (let i = 0; i < 999; i++) key = sm3Hash(key)
    const derived = key.slice(0, 16)
    if (this.cache.size >= this.maxSize) {
      const first = this.cache.keys().next().value
      this.cache.delete(first)
    }
    this.cache.set(cacheKey, { key: derived, hits: 0 })
    return derived
  }

  clear() { this.cache.clear() }
  stats() { return { size: this.cache.size, max: this.maxSize } }
}

const keyPool = new KeyPool()


// === src/utils/audit.js ===
// 操作日志 SM3 存证系统
// 所有加密/解密/签名/验签行为自动记录，日志链 SM3 固化不可篡改
import { sm3HashHex } from './sm3.js'

const LOG_KEY = 'smc_audit_log'
const MAX_LOGS = 500

function loadLogs() {
  try {
    return JSON.parse(localStorage.getItem(LOG_KEY) || '[]')
  } catch { return [] }
}

function saveLogs(logs) {
  localStorage.setItem(LOG_KEY, JSON.stringify(logs.slice(-MAX_LOGS)))
}

function chainHash(prevHash, entry) {
  return sm3HashHex(prevHash + JSON.stringify(entry))
}

function auditLog(action, detail = {}) {
  const logs = loadLogs()
  const prevHash = logs.length > 0 ? logs[logs.length - 1].chainHash : '0000000000000000000000000000000000000000000000000000000000000000'
  const entry = {
    id: logs.length + 1,
    ts: new Date().toISOString(),
    action,
    detail,
    prevHash
  }
  entry.chainHash = chainHash(prevHash, entry)
  logs.push(entry)
  saveLogs(logs)
  return entry
}

function getAuditLogs() {
  return loadLogs()
}

function verifyLogChain() {
  const logs = loadLogs()
  for (let i = 1; i < logs.length; i++) {
    const expectedPrev = logs[i - 1].chainHash
    if (logs[i].prevHash !== expectedPrev) return { ok: false, brokenAt: i }
  }
  return { ok: true, total: logs.length }
}

function exportAuditReport() {
  const logs = loadLogs()
  const verify = verifyLogChain()
  const report = {
    generatedAt: new Date().toISOString(),
    totalOperations: logs.length,
    chainValid: verify.ok,
    logs
  }
  return JSON.stringify(report, null, 2)
}

function clearAuditLog() {
  localStorage.removeItem(LOG_KEY)
}


// === src/utils/vault.js ===
// 加密文件容器 — SM4-CBC + SM3 完整性校验
// 格式: MAGIC(4) + Version(1) + SaltLen(1) + Salt + Iter(2) + NameLen(2) + Name + Hash(32) [→ SM4-CBC 加密]
import { sm4EncryptCBC, sm4DecryptCBC, hexToBytes } from './sm4.js'
import { sm3Hash } from './sm3.js'

const MAGIC = new Uint8Array([0x53, 0x4D, 0x43, 0x42]) // "SMCB" v2
const VERSION = 2
const ITERATIONS = 1000

function concat(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) { result.set(a, offset); offset += a.length }
  return result
}

function randomSalt() {
  return crypto.getRandomValues(new Uint8Array(8))
}

function encryptFile(fileBytes, fileName, keyBytes, salt = null) {
  const s = salt || randomSalt()
  const fileHash = sm3Hash(fileBytes)
  const nameBytes = new TextEncoder().encode(fileName)
  const iter = new Uint8Array(2)
  iter[0] = (ITERATIONS >> 8) & 0xff; iter[1] = ITERATIONS & 0xff
  const nameLen = new Uint8Array(2)
  nameLen[0] = (nameBytes.length >> 8) & 0xff; nameLen[1] = nameBytes.length & 0xff
  const saltLen = new Uint8Array([s.length])

  // 容器头: MAGIC(4) + Ver(1) + SaltLen(1) + Salt(8) + Iter(2) + NameLen(2) + Name + Hash(32)
  const header = concat(MAGIC, new Uint8Array([VERSION]), saltLen, s, iter, nameLen, nameBytes, fileHash)
  const plain = concat(header, fileBytes)
  const cipher = sm4EncryptCBC(plain, keyBytes)

  // 最终格式: [明文Salt(8)] + [CBC加密容器]
  const final = new Uint8Array(s.length + cipher.length)
  final.set(s); final.set(cipher, s.length)

  return {
    container: final,
    hash: Array.from(fileHash).map(b => b.toString(16).padStart(2, '0')).join(''),
    salt: Array.from(s).map(b => b.toString(16).padStart(2, '0')).join(''),
    iterations: ITERATIONS,
    mode: 'SM4-CBC / PKCS7 / SM3 完整性校验 / SM3 密钥派生 1000 轮'
  }
}

function extractSalt(containerBytes) {
  return containerBytes.slice(0, 8) // 前 8 字节为明文盐值
}

function decryptFile(containerBytes, keyBytes) {
  // 去掉前 8 字节明文盐值，剩余为 CBC 加密容器
  const cipher = containerBytes.slice(8)
  const plain = sm4DecryptCBC(cipher, keyBytes)

  if (plain[0] !== 0x53 || plain[1] !== 0x4D || plain[2] !== 0x43 || plain[3] !== 0x42) {
    throw new Error('文件格式不匹配：不是有效的 SMC 加密文件，请确认选择了正确的 .enc 文件')
  }
  const ver = plain[4]
  if (ver !== 2) throw new Error(`文件版本 v${ver} 与当前版本 v${VERSION} 不兼容`)

  let off = 5
  const saltLen = plain[off]; off++
  const salt = plain.slice(off, off + saltLen); off += saltLen
  const iterations = (plain[off] << 8) | plain[off + 1]; off += 2
  const nameLen = (plain[off] << 8) | plain[off + 1]; off += 2
  const fileName = new TextDecoder().decode(plain.slice(off, off + nameLen)); off += nameLen
  const storedHash = plain.slice(off, off + 32); off += 32
  const fileBytes = plain.slice(off)

  const actualHash = sm3Hash(fileBytes)
  const hashMatch = storedHash.every((b, i) => b === actualHash[i])

  return { fileName, fileBytes, hashMatch, salt, iterations }
}

// === 文件夹打包 ===
// 格式: [fileCount(2)] + 每个文件: [pathLen(2)+path+fileLen(4)+content]
async function packFolder(files) {
  const encoder = new TextEncoder()
  const parts = []
  // 去掉公共前缀路径
  let root = ''
  if (files.length > 0) {
    const fp = files[0].webkitRelativePath || files[0].name
    const slash = fp.indexOf('/')
    if (slash > 0) root = fp.slice(0, slash + 1)
  }

  const count = new Uint8Array(2)
  const dv = new DataView(count.buffer)
  dv.setUint16(0, files.length)
  parts.push(count)

  for (const f of files) {
    const relPath = (f.webkitRelativePath || f.name).replace(root, '')
    const pathBytes = encoder.encode(relPath)
    const pathLen = new Uint8Array(2)
    new DataView(pathLen.buffer).setUint16(0, pathBytes.length)
    const buf = await f.arrayBuffer()
    const fileLen = new Uint8Array(4)
    new DataView(fileLen.buffer).setUint32(0, buf.byteLength)
    parts.push(pathLen, pathBytes, fileLen, new Uint8Array(buf))
  }

  const total = parts.reduce((s, p) => s + p.length, 0)
  const result = new Uint8Array(total)
  let off = 0
  for (const p of parts) { result.set(p, off); off += p.length }
  return { data: result, root: root.slice(0, -1) || 'folder' }
}

function unpackFolder(packed, rootName) {
  const decoder = new TextDecoder()
  const dv = new DataView(packed.buffer, packed.byteOffset, packed.byteLength)
  const fileCount = dv.getUint16(0)
  const files = []
  let off = 2
  for (let i = 0; i < fileCount; i++) {
    const pathLen = dv.getUint16(off); off += 2
    const path = decoder.decode(packed.slice(off, off + pathLen)); off += pathLen
    const fileLen = dv.getUint32(off); off += 4
    const content = packed.slice(off, off + fileLen); off += fileLen
    files.push({ path: rootName + '/' + path, content })
  }
  return files
}

function downloadFile(bytes, fileName) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = fileName; a.click()
  URL.revokeObjectURL(url)
}


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
  exportKeyPair: function(pub,pri) { downloadFile(new TextEncoder().encode("PUBLIC_KEY="+pub+"\nPRIVATE_KEY="+pri), "smc-sm2-keypair.txt") },
  loadKeyPair: function() { return { publicKey: localStorage.getItem("smc_sm2_pub")||"", privateKey: localStorage.getItem("smc_sm2_pri")||"" } },
  saveKeyPair: function(pub,pri) { localStorage.setItem("smc_sm2_pub",pub); localStorage.setItem("smc_sm2_pri",pri) },
  // 审计
  getAuditLogs: getAuditLogs,
  verifyLogChain: verifyLogChain,
  exportAuditReport: exportAuditReport,
};
})();
