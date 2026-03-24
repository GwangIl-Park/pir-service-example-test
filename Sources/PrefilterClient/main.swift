import Foundation
import ArgumentParser

struct PrefilterClient: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "PrefilterClient",
        abstract: "Check whether a keyword is possibly contained in data/prefilter.json Bloom filter.")

    @Option(name: [.short, .long], help: "Path to prefilter Bloom filter JSON file.")
    var prefilterFile: String = "data/prefilter.json"

    @Argument(help: "Keyword (URL) to check against the Bloom filter.")
    var keyword: String

    func run() async throws {
        let prefilterURL = URL(fileURLWithPath: prefilterFile)
        let data = try Data(contentsOf: prefilterURL)
        let filter = try JSONDecoder().decode(BloomFilter.self, from: data)

        let contains = try bloomFilter(filter, mightContain: keyword)

        if contains {
            print("maybe") // Bloom filter 상 '포함 가능성 있음' (false positive 가능)
        } else {
            print("no")    // Bloom filter 상 '확실히 없음'
        }
    }

    /// BloomFilter에 주어진 keyword가 포함되어 있다고 판단되는지 검사.
    private func bloomFilter(_ filter: BloomFilter, mightContain value: String) throws -> Bool {
        guard let data = value.data(using: .utf8),
              let bits = filter.data
        else {
            throw BloomFilterError.encodingIssue(message: "Unable to encode string '\(value)' to UTF8")
        }

        for count in 0..<filter.hashCount {
            let fnv = data.fnvHash()
            let murmur = data.murmurHash3(seed: filter.murmurSeed)
            let index = Int((fnv &+ count &* murmur) % filter.bitCount)
            if !bits.bit(at: index) {
                // 하나라도 0이면 Bloom filter 특성상 "포함되지 않음"이 확실하다.
                return false
            }
        }
        // 모든 비트가 1이면 "포함될 가능성이 있다" (거짓 양성은 허용).
        return true
    }
}

// This executable is used similarly to PIRService main.swift; avoid top-level `await`.
let group = DispatchGroup()
group.enter()
let task = Task.detached(priority: .userInitiated) {
    defer { group.leave() }
    await PrefilterClient.main()
}
_ = task
group.wait()

