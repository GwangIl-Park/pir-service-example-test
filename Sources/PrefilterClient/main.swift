import ArgumentParser
import BloomFilterCore
import Foundation

struct PrefilterClient: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "PrefilterClient",
        abstract: """
        Bloom filter JSON(단일 파일에 data 포함, 또는 메타데이터 + `.dat` 분리 형식)에 대해 키워드 포함 여부를 조회합니다.
        """)

    @Option(name: [.short, .long], help: "Prefilter JSON 경로 (기본: data2/prefilter.json).")
    var prefilterFile: String = "data2/prefilter.json"

    @Argument(help: "Keyword (URL) to check against the Bloom filter.")
    var keyword: String

    func run() async throws {
        let prefilterURL = URL(fileURLWithPath: prefilterFile)
        let raw = try Data(contentsOf: prefilterURL)
        let filter: BloomFilter
        if let json = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
           json["sha256"] != nil
        {
            filter = try BloomFilter.load(fromJSONAt: prefilterURL)
        } else {
            filter = try JSONDecoder().decode(BloomFilter.self, from: raw)
        }
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

