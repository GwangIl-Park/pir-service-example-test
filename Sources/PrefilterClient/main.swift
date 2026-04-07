import ArgumentParser
import BloomFilterCore
import Foundation

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
        let contains = filter.contains(keyword)

        if contains {
            print("maybe") // Bloom filter 상 '포함 가능성 있음' (false positive 가능)
        } else {
            print("no")    // Bloom filter 상 '확실히 없음'
        }
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

