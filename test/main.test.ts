import { describe, it, expect } from "bun:test"
import { sha256 } from "../src/main"

describe("sha256", () => {
    it("hashes empty string", () => expect(sha256("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    it("hashes single character", () => expect(sha256("a")).toBe("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"))
    it("hashes 'abc'", () => expect(sha256("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
    it("hashes 'message digest'", () => expect(sha256("message digest")).toBe("f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"))
    it("hashes alphabet", () => expect(sha256("abcdefghijklmnopqrstuvwxyz")).toBe("71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"))
    it("hashes NIST test vector (56 chars)", () => expect(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))
    it("hashes 'The quick brown fox jumps over the lazy dog'", () => expect(sha256("The quick brown fox jumps over the lazy dog")).toBe("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"))
    it("hashes cyrillic text", () => expect(sha256("Привет мир")).toBe("830d1964dc8673182a40f9adebf598960d37fbe200405b249774ecfa5b465748"))
    it("hashes 55 chars (edge: fits in one block with padding)", () => expect(sha256("a".repeat(55))).toBe("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"))
    it("hashes 56 chars (edge: exactly fills block before length append)", () => expect(sha256("a".repeat(56))).toBe("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"))
    it("hashes 64 chars (edge: exactly one block)", () => expect(sha256("a".repeat(64))).toBe("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"))
    it("hashes 100 chars", () => expect(sha256("a".repeat(100))).toBe("2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"))
    it("hashes 1K chars", () => expect(sha256("a".repeat(1000))).toBe("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"))
    it("hashes 1M chars (performance smoke test)", () => expect(sha256("a".repeat(1_000_000))).toBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"))
    it("hashes 119 chars (edge: second block almost full)", () => expect(sha256("a".repeat(119))).toBe("31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"))
    it("hashes 120 chars (edge: second block exactly at boundary)", () => expect(sha256("a".repeat(120))).toBe("2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"))
    it("hashes emoji (surrogate pairs)", () => expect(sha256("🎉")).toBe("6146299cd54818a0e659eb6ac88e80f6f8f70536bbbd962d36973f2d2323f26c"))
    it("hashes mixed text with emoji", () => expect(sha256("Hello 👋 World 🌍")).toBe("c15ee319b97bfd23fa98590baf0b47d1f7b7b81f9e5bf99d8275867e2e4a32a2"))
    it("produces different hashes for different inputs", () => {
        const h1 = sha256("hello"), h2 = sha256("Hello"), h3 = sha256("hello!")
        expect(h1).not.toBe(h2); expect(h1).not.toBe(h3); expect(h2).not.toBe(h3)
    })
    it("produces consistent results for same input", () => {
        const input = "consistency test"
        const h1 = sha256(input), h2 = sha256(input), h3 = sha256(input)
        expect(h1).toBe(h2); expect(h2).toBe(h3)
    })
})

describe("sha256 performance", () => {
    it("hashes 100K short strings under 1 second", () => {
        const iterations = 100_000, start = performance.now()
        for (let i = 0; i < iterations; i++) sha256("test" + i)
        const elapsed = performance.now() - start
        console.log(`    → ${(iterations / elapsed * 1000).toFixed(0)} ops/sec`)
        expect(elapsed).toBeLessThan(1000)
    })

    it("hashes 10k medium strings (100 chars) under 1 second", () => {
        const input = "a".repeat(100), iterations = 10_000, start = performance.now()
        for (let i = 0; i < iterations; i++) sha256(input + i)
        const elapsed = performance.now() - start
        console.log(`    → ${(iterations / elapsed * 1000).toFixed(0)} ops/sec`)
        expect(elapsed).toBeLessThan(1000)
    })

    it("hashes 1k long strings (10k chars) under 1 second", () => {
        const input = "a".repeat(10_000), iterations = 1_000, start = performance.now()
        for (let i = 0; i < iterations; i++) sha256(input + i)
        const elapsed = performance.now() - start
        console.log(`    → ${(iterations / elapsed * 1000).toFixed(0)} ops/sec`)
        expect(elapsed).toBeLessThan(1000)
    })

    it("hashes 100 very long strings (1M chars) under 5 seconds", () => {
        const input = "a".repeat(1_000_000), iterations = 100, start = performance.now()
        for (let i = 0; i < iterations; i++) sha256(input + (i % 10))
        const elapsed = performance.now() - start
        console.log(`    → ${(iterations / elapsed * 1000).toFixed(0)} ops/sec`)
        expect(elapsed).toBeLessThan(5000)
    })

    it("sustains throughput above 50 MB/s", () => {
        const chunk = "a".repeat(1000), iterations = 50_000, totalBytes = iterations * chunk.length, start = performance.now()
        for (let i = 0; i < iterations; i++) sha256(chunk)
        const elapsed = performance.now() - start, mbPerSec = (totalBytes / 1024 / 1024) / (elapsed / 1000)
        console.log(`    → ${mbPerSec.toFixed(2)} MB/sec`)
        console.log(`    → ${(iterations / elapsed * 1000).toFixed(0)} ops/sec`)
        expect(mbPerSec).toBeGreaterThan(50)
    })

    it("hashes a 500MB string without crashing", () => {
        const chunk = "x".repeat(10_000_000), parts: string[] = []
        for (let i = 0; i < 50; i++) parts.push(chunk + i)
        const giant = parts.join(""); parts.length = 0
        const start = performance.now(), hash = sha256(giant), elapsed = performance.now() - start
        expect(hash).toHaveLength(64)
    })

    it("allocates 2GB of intermediate strings and hashes them all", () => {
        const results: string[] = [], chunk = "z".repeat(1_000_000)
        for (let i = 0; i < 2000; i++) results.push(sha256(chunk + i))
        expect(results.every(h => h.length === 64)).toBe(true)
    })

    it("creates a 1GB string via repeated doubling and hashes it", () => {
        let blob = "a"
        for (let i = 0; i < 30; i++) blob += blob
        const hash = sha256(blob)
        expect(hash).toHaveLength(64)
    })
})
