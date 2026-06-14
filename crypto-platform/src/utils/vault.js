// 加密文件容器 — SM4-CBC + SM3 完整性校验
// 格式: MAGIC(4) + Version(1) + SaltLen(1) + Salt + Iter(2) + NameLen(2) + Name + Hash(32) [→ SM4-CBC 加密]
import { sm4EncryptCBC, sm4DecryptCBC, hexToBytes, getRandomBytes } from './sm4.js'
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
  return getRandomBytes(8)
}

export function encryptFile(fileBytes, fileName, keyBytes, salt = null) {
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

export function extractSalt(containerBytes) {
  return containerBytes.slice(0, 8) // 前 8 字节为明文盐值
}

export function decryptFile(containerBytes, keyBytes) {
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
  if (!hashMatch) throw new Error('完整性校验失败：文件可能已被篡改或密码错误')

  return { fileName, fileBytes, hashMatch, salt, iterations }
}

// === 文件夹打包 ===
// 格式: [fileCount(2)] + 每个文件: [pathLen(2)+path+fileLen(4)+content]
export async function packFolder(files) {
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

export function unpackFolder(packed, rootName) {
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

export function downloadFile(bytes, fileName) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = fileName; a.click()
  URL.revokeObjectURL(url)
}
