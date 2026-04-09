import BloomFilterCore
import Foundation

actor PrefilterStore {
    struct Snapshot: Codable, Sendable {
        let usecase: String
        let generatedAt: Date
        let sourceURLCount: Int
        let sourceFile: String
        let outputFile: String
        let version: String?
        let size: Int
        let sha256: String
    }

    private var snapshots: [String: Snapshot] = [:]

    func set(_ snapshot: Snapshot) {
        snapshots[snapshot.usecase] = snapshot
    }

    func setAll(_ snapshots: [String: Snapshot]) {
        self.snapshots = snapshots
    }

    func get(usecase: String) -> Snapshot? {
        snapshots[usecase]
    }
}
