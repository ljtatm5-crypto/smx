import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      entry: 'src/utils/smc-sdk.js',
      name: 'SMC',
      fileName: 'smc-sdk',
      formats: ['umd']
    },
    outDir: 'sdk-dist'
  }
})
