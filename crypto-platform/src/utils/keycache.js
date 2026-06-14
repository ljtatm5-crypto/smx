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

export const keyPool = new KeyPool()
