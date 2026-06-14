// SM2 椭圆曲线公钥密码算法 (GB/T 32918-2016)
// 基于 256-bit 素数域上的椭圆曲线: y² = x³ + ax + b
import { sm3Hash } from './sm3.js'

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

export function sm2GenerateKeyPair() {
  let d
  do {
    const bytes = crypto.getRandomValues(new Uint8Array(32))
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    d = BigInt('0x' + hex)
  } while (d >= N || d === 0n)

  const pubPoint = pointMul(d, G)
  return {
    privateKey: bytesToHex32(d),
    publicKey: '04' + bytesToHex32(pubPoint.x) + bytesToHex32(pubPoint.y)
  }
}

export function sm2Sign(message, privateKeyHex, publicKeyHex) {
  const d = BigInt('0x' + privateKeyHex)
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : new Uint8Array(message)

  // ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
  const ZA = computeZA(publicKeyHex)

  // e = SM3(ZA || M)
  const eHash = hashZAandMsg(ZA, msgBytes)
  const e = BigInt('0x' + bytesToHex(eHash))

  let r, s
  while (true) {
    const kBytes = crypto.getRandomValues(new Uint8Array(32))
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

export function sm2Verify(message, signature, publicKeyHex) {
  const r = BigInt('0x' + signature.r)
  const s = BigInt('0x' + signature.s)

  if (r < 1n || r >= N || s < 1n || s >= N) return false

  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : new Uint8Array(message)
  const ZA = computeZA(publicKeyHex)
  const eHash = hashZAandMsg(ZA, msgBytes)
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

  const pubX = publicKeyHex.slice(2, 66)
  const pubY = publicKeyHex.slice(66, 130)

  const zaInput = hexToBytes(entla + id + aHex + bHex + gxHex + gyHex + pubX + pubY)
  return sm3Hash(zaInput)
}

function hashZAandMsg(ZA, message) {
  const combined = new Uint8Array(ZA.length + message.length)
  combined.set(ZA)
  combined.set(message, ZA.length)
  return sm3Hash(combined)
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

export { computeZA }
