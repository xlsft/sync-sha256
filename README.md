# sync-sha256

Zero-dependency, synchronous SHA-256 for TypeScript. Drop-in replacement for `js-sha256` with first-class type safety.

[**Demo**](https://xlsft.github.io/sync-sha256/)

- **No dependencies** — pure TypeScript, no `crypto` polyfills
- **Synchronous** — no `await`, works in sync contexts
- **UTF-8** — correct handling of Unicode, including surrogate pairs (emoji, CJK)
- **Zero allocations** on repeated calls (reuses internal `Uint32Array`)
- **Tree-shakeable** — only import what you use

## Install

```bash
npm install sync-sha256
# or
bun add sync-sha256
```

## Usage

```typescript
import { sha256 } from 'sync-sha256'

sha256('') // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sha256('The quick brown fox jumps over the lazy dog') // d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592

// UTF-8
sha256('中文') // 72726d8818f693066ceb69afa364218b692e62ea92b385782363780f47529c21
sha256('🎉')   // 6146299cd54818a0e659eb6ac88e80f6f8f70536bbbd962d36973f2d2323f26c
```

## API

### `sha256(message: string): string`

Returns a 64-character hex string.

```typescript
import { sha256 } from 'sync-sha256'

const hash = sha256('Message to hash')
// => 'f7bc83f430538424b13298e6aa6fb1438f4d89a51f0ed5d0a63f5b3e1230c20e'
```

## Differences from `js-sha256`

| Package     | Size   | SHA-224 | HMAC | Streaming |
| ----------- | ------ | ------- | ---- | --------- |
| `js-sha256` | ~3.5KB | ✅       | ✅    | ✅         |
| `sync-sha256` | ~2KB   | ❌       | ❌    | ❌         |



**Use `js-sha256`** if you need SHA-224, HMAC, streaming, or byte array input.

**Use `sync-sha256`** if you need a smaller, typed, synchronous string-to-hex hasher.

## Benchmarks

Bun 1.3.2, AMD Ryzen 5 7500F:

| Test                               | Throughput        | Time  |
| ---------------------------------- | ----------------- | ----- |
| 100K × 5-byte strings              | **929K ops/sec**  | 108ms |
| 10K × 100-byte strings             | **610K ops/sec**  | 16ms  |
| 1K × 10KB strings                  | **11.1K ops/sec** | 91ms  |
| 100 × 1MB strings                  | **117 ops/sec**   | 862ms |
| Sustained throughput (50MB chunks) | **108 MB/s**      | 443ms |
| Single 500MB string                | —                 | 5.0s  |
| 2K × 1MB strings (2GB total alloc) | —                 | 17.7s |
| Single 1GB string (doubling)       | —                 | 9.7s  |

## License

MIT
