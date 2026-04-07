import BloomFilterCore
import Foundation

actor PrefilterStore {
    struct Snapshot: Codable, Sendable {
        let filter: BloomFilter
        let generatedAt: Date
        let sourceURLCount: Int
        let sourceFile: String
        let outputFile: String
    }

    private var snapshot: Snapshot?

    func set(_ snapshot: Snapshot?) {
        self.snapshot = snapshot
    }

    func get() -> Snapshot? {
        snapshot
    }
}
