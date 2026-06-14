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

export function sm3Hash(message) {
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

export function sm3HashHex(message) {
  return Array.from(sm3Hash(message)).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function sm3HashFile(arrayBuffer) {
  return sm3Hash(new Uint8Array(arrayBuffer))
}

export function sm3HMAC(key, message) {
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

export function sm3HMACHex(key, message) {
  return Array.from(sm3HMAC(key, message)).map(b => b.toString(16).padStart(2, '0')).join('')
}
